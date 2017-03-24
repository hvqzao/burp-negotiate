package hvqzao.negotiate;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import javax.swing.DefaultListModel;

public class NegotiatePane extends javax.swing.JPanel {

    private static final String PRESET_USERDOMAIN = "userDomain";
    private static final String PRESET_MODE = "mode";
    private static final String PRESET_SCOPE = "scope";
    private static final String MODE_PROACTIVE = "Proactive";
    private static final String MODE_REACTIVE = "Reactive";
    private Negotiate negotiate;
    private IBurpExtenderCallbacks callbacks;
    private DefaultListModel scopeModel;

    /**
     * Creates new form NegotiatePane
     */
    public NegotiatePane() {
        initComponents();
    }

    public void initialize() {
        this.callbacks = BurpExtender.getCallbacks();

        // help button
        helpButton.setIcon(BurpExtender.getIconHelp());
        helpButton.setEnabled(false);
        callbacks.customizeUiComponent(helpButton);

        // defaults button
        defaultsButton.setIcon(BurpExtender.getIconDefaults());
        callbacks.customizeUiComponent(defaultsButton);

        // buttons, fields, lists
        callbacks.customizeUiComponent(userDomainField);
        callbacks.customizeUiComponent(passwordField);
        callbacks.customizeUiComponent(urlField);
        callbacks.customizeUiComponent(addButton);
        callbacks.customizeUiComponent(removeButton);
        callbacks.customizeUiComponent(clearButton);
        callbacks.customizeUiComponent(loginButton);
        callbacks.customizeUiComponent(logoutButton);
        callbacks.customizeUiComponent(clearCacheButton);

        // scope list model
        scopeModel = new DefaultListModel();
        scopeList.setModel(scopeModel);

        // split pane
        scopeSplitPane.setDividerSize(10);
        scopeSplitPane.setUI(new GlyphSplitPaneUI(getBackground()));

        // state
        setDefaults();

        // actions
        defaultsButton.addActionListener((e) -> {
            setDefaults();
        });
        modeComboBox.addActionListener((e) -> {
            setProactive();
        });
        addButton.addActionListener((e) -> {
            add();
        });
        removeButton.addActionListener((e) -> {
            remove();
        });
        clearButton.addActionListener((e) -> {
            clear();
        });
        loginButton.addActionListener((e) -> {
            login();
        });
        logoutButton.addActionListener((e) -> {
            logout();
        });
        clearCacheButton.addActionListener((e) -> {
            clearCache();
        });
    }

    /**
     * Display error message.
     *
     * @param text
     */
    private void setError(String text) {
        errorLabel.setText(new StringBuilder("<html><p style='color:#e58900;font-style:italic'>").append(text).append("</p></html>").toString());
    }

    /**
     * Hide error message.
     *
     */
    private void clearError() {
        setError("");
    }

    /**
     * Set login / logout / clearCache buttons enabled state depending on
     * {@code isLoggedIn} state.
     *
     * @param isLoggedIn
     */
    private void setLoggedInState(boolean isLoggedIn) {
        loginButton.setEnabled(isLoggedIn == false);
        logoutButton.setEnabled(isLoggedIn);
        clearCacheButton.setEnabled(isLoggedIn);
    }

    /**
     * Restore UI to defaults.
     *
     */
    private void setDefaults() {
        if (negotiate != null) {
            callbacks.removeHttpListener(negotiate);
        }
        userDomainField.setText("");
        passwordField.setText("");
        urlField.setText("");
        scopeModel.removeAllElements();
        //scopeList.removeAll();
        setLoggedInState(false);
        modeComboBox.setSelectedItem(MODE_REACTIVE);

        loadSavedPresets();

        // check unlimited JCE
        if (Negotiate.isUnlimitedJCE() == false) {
            setError("Unlimited Strength Java(TM) Cryptography Extension Policy Files not found! Extension might fail to work!");
        } else {
            clearError();
        }

        userDomainField.requestFocus();
    }

    /**
     * is Proactive mode set?
     *
     * @return status
     */
    private boolean isProactive() {
        return MODE_PROACTIVE.equals(modeComboBox.getSelectedItem());
    }

    /**
     * Notify mode change handler about mode of operation change.
     *
     */
    private void setProactive() {
        if (negotiate != null) {
            negotiate.setProactive(isProactive());
        }

        savePresets();
    }

    /**
     * Add scope item.
     *
     * @param textUrl
     * @param verbose
     */
    private void add(String textUrl, boolean verbose) {
        URL url = getURL(textUrl);
        if (url != null) {
            if (negotiate != null) {
                negotiate.add(url);
            }
            scopeModel.addElement(textUrl);
            urlField.setText("");
            clearError();
        } else {
            if (verbose) {
                setError("Failed to parse URL!");
            }
        }
    }

    /**
     * Add scope item from {@code urlField}.
     *
     */
    private void add() {
        String textUrl = urlField.getText();
        add(textUrl, true);

        savePresets();
    }

    /**
     * Remove selected scope items.
     *
     */
    private void remove() {
        scopeList.getSelectedValuesList().forEach((String urlText) -> {
            URL url = getURL(urlText);
            if (negotiate != null) {
                negotiate.remove(url);
            }
            scopeModel.removeElement(urlText);
            urlField.setText(urlText);
            urlField.requestFocus();
        });

        savePresets();
    }

    /**
     * Clear scope.
     *
     */
    private void clear() {
        if (negotiate != null) {
            negotiate.clear();
        }
        scopeModel.clear();

        savePresets();
    }

    /**
     * Save current presets to Burp config. Password is not saved.
     *
     */
    private void savePresets() {
        callbacks.saveExtensionSetting(PRESET_USERDOMAIN, userDomainField.getText());
        callbacks.saveExtensionSetting(PRESET_MODE, (String) modeComboBox.getSelectedItem());
        callbacks.saveExtensionSetting(PRESET_SCOPE, String.join("|", getScope()));
    }

    /**
     * Load current presets from Burp config.
     *
     */
    private void loadSavedPresets() {
        String userDomainPreset = callbacks.loadExtensionSetting(PRESET_USERDOMAIN);
        if (userDomainPreset != null) {
            userDomainField.setText(userDomainPreset);
        }
        String modePreset = callbacks.loadExtensionSetting(PRESET_MODE);
        if (modePreset != null && Arrays.asList(MODE_PROACTIVE, MODE_REACTIVE).contains(modePreset)) {
            modeComboBox.setSelectedItem(modePreset);
        }
        String scopeStringPreset = callbacks.loadExtensionSetting(PRESET_SCOPE);
        if (scopeStringPreset != null) {
            Arrays.asList(scopeStringPreset.split("\\|")).stream().forEach((String textUrl) -> {
                add(textUrl, false);
            });
        }
    }

    /**
     * Get list of scope urls (Strings).
     *
     * @return
     */
    private List<String> getScope() {
        return Arrays.asList(scopeModel.toArray()).stream().map((Object urlObject) -> {
            return (String) urlObject;
        }).collect(Collectors.toList());
    }

    /**
     * Login button on click activity.
     *
     */
    private void login() {
        String username;
        String domain;
        String password;
        String userDomainText = userDomainField.getText();
        List<String> userDomain = Arrays.asList(userDomainText.split("@", 2));
        if (userDomain.size() < 2) {
            setError("Invalid format of Username @ Domain field!");
            return;
        }
        username = userDomain.get(0);
        domain = userDomain.get(1);
        password = new String(passwordField.getPassword());
        negotiate = new Negotiate(domain, username, password, isProactive());
        if (negotiate.login()) {
            setLoggedInState(true);
            negotiate.register();
            clearError();

            // add scope from list view to negotiate
            getScope().forEach((String urlText) -> {
                URL url = getURL(urlText);
                negotiate.add(url);
            });

            savePresets();
        } else {
            setError("Login failed!");
            negotiate = null;
        }
    }

    /**
     * Logout button on click activity.
     *
     */
    private void logout() {
        negotiate.clear();
        negotiate.logout();
        setLoggedInState(false);
    }

    /**
     * Clear cache button on click activity.
     *
     */
    private void clearCache() {
        negotiate.clearMapping();
        negotiate.clearCache();
    }

    /**
     * Convert String to URL. Returns NULL when failed.
     *
     * @param textUrl
     * @return
     */
    private URL getURL(String textUrl) {
        URL url = null;
        try {
            url = new URL(textUrl);
        } catch (MalformedURLException ex) {
            // do nothing
        }
        return url;
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jPanel1 = new javax.swing.JPanel();
        helpButton = new javax.swing.JButton();
        defaultsButton = new javax.swing.JButton();
        optionsTitle = new javax.swing.JLabel();
        jLabel1 = new javax.swing.JLabel();
        jPanel3 = new javax.swing.JPanel();
        userDomainField = new javax.swing.JTextField();
        jLabel3 = new javax.swing.JLabel();
        jPanel4 = new javax.swing.JPanel();
        jLabel4 = new javax.swing.JLabel();
        passwordField = new javax.swing.JPasswordField();
        errorLabel = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        addButton = new javax.swing.JButton();
        removeButton = new javax.swing.JButton();
        loginButton = new javax.swing.JButton();
        logoutButton = new javax.swing.JButton();
        clearCacheButton = new javax.swing.JButton();
        scopeSplitPane = new javax.swing.JSplitPane();
        jPanel2 = new javax.swing.JPanel();
        jPanel5 = new javax.swing.JPanel();
        urlField = new javax.swing.JTextField();
        jScrollPane1 = new javax.swing.JScrollPane();
        scopeList = new javax.swing.JList<>();
        clearButton = new javax.swing.JButton();
        jPanel6 = new javax.swing.JPanel();
        jLabel5 = new javax.swing.JLabel();
        modeComboBox = new javax.swing.JComboBox<>();

        setBorder(javax.swing.BorderFactory.createEmptyBorder(5, 5, 5, 5));

        helpButton.setMargin(new java.awt.Insets(0, 0, 0, 0));
        helpButton.setMaximumSize(new java.awt.Dimension(24, 24));
        helpButton.setMinimumSize(new java.awt.Dimension(24, 24));
        helpButton.setPreferredSize(new java.awt.Dimension(24, 24));

        defaultsButton.setMargin(new java.awt.Insets(0, 0, 0, 0));
        defaultsButton.setMaximumSize(new java.awt.Dimension(24, 24));
        defaultsButton.setMinimumSize(new java.awt.Dimension(24, 24));
        defaultsButton.setPreferredSize(new java.awt.Dimension(24, 24));

        optionsTitle.setText("<html><b style='color:#e58900;font-size:10px'>Negotiate</b></html>");
        optionsTitle.setToolTipText("");

        jLabel1.setText("<html>The purpose of this extension is to make it possible to perform Negotiate (Kerberos / SPNEGO) authentication in Burp.</html>");

        jLabel3.setText("Username @ Domain:");

        javax.swing.GroupLayout jPanel3Layout = new javax.swing.GroupLayout(jPanel3);
        jPanel3.setLayout(jPanel3Layout);
        jPanel3Layout.setHorizontalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel3Layout.createSequentialGroup()
                .addComponent(jLabel3)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 13, Short.MAX_VALUE)
                .addComponent(userDomainField, javax.swing.GroupLayout.PREFERRED_SIZE, 188, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
        );
        jPanel3Layout.setVerticalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                .addComponent(userDomainField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addComponent(jLabel3))
        );

        jLabel4.setText("Password:");

        errorLabel.setText("<html><p style='color:#e58900;font-style:italic'>aaa</p></html>");
        errorLabel.setToolTipText("");

        javax.swing.GroupLayout jPanel4Layout = new javax.swing.GroupLayout(jPanel4);
        jPanel4.setLayout(jPanel4Layout);
        jPanel4Layout.setHorizontalGroup(
            jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel4Layout.createSequentialGroup()
                .addComponent(jLabel4)
                .addGap(65, 65, 65)
                .addComponent(passwordField, javax.swing.GroupLayout.PREFERRED_SIZE, 187, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(errorLabel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(0, 0, Short.MAX_VALUE))
        );
        jPanel4Layout.setVerticalGroup(
            jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                .addComponent(jLabel4)
                .addComponent(passwordField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addComponent(errorLabel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
        );

        jLabel2.setText("Scope:");

        addButton.setText("Add");

        removeButton.setText("Remove");

        loginButton.setText("Login");

        logoutButton.setText("Logout");

        clearCacheButton.setText("Clear cache");

        scopeSplitPane.setDividerLocation(350);

        javax.swing.GroupLayout jPanel2Layout = new javax.swing.GroupLayout(jPanel2);
        jPanel2.setLayout(jPanel2Layout);
        jPanel2Layout.setHorizontalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 0, Short.MAX_VALUE)
        );
        jPanel2Layout.setVerticalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 167, Short.MAX_VALUE)
        );

        scopeSplitPane.setRightComponent(jPanel2);

        jScrollPane1.setViewportView(scopeList);

        javax.swing.GroupLayout jPanel5Layout = new javax.swing.GroupLayout(jPanel5);
        jPanel5.setLayout(jPanel5Layout);
        jPanel5Layout.setHorizontalGroup(
            jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(urlField)
            .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 349, Short.MAX_VALUE)
        );
        jPanel5Layout.setVerticalGroup(
            jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel5Layout.createSequentialGroup()
                .addComponent(urlField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 141, Short.MAX_VALUE))
        );

        scopeSplitPane.setLeftComponent(jPanel5);

        clearButton.setText("Clear");

        jLabel5.setText("Mode:");

        modeComboBox.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "Reactive", "Proactive" }));

        javax.swing.GroupLayout jPanel6Layout = new javax.swing.GroupLayout(jPanel6);
        jPanel6.setLayout(jPanel6Layout);
        jPanel6Layout.setHorizontalGroup(
            jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel6Layout.createSequentialGroup()
                .addComponent(jLabel5)
                .addGap(86, 86, 86)
                .addComponent(modeComboBox, 0, 189, Short.MAX_VALUE))
        );
        jPanel6Layout.setVerticalGroup(
            jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                .addComponent(jLabel5)
                .addComponent(modeComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
        );

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addComponent(helpButton, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(optionsTitle, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(0, 0, Short.MAX_VALUE))
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addComponent(defaultsButton, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel1, javax.swing.GroupLayout.DEFAULT_SIZE, 670, Short.MAX_VALUE)
                            .addGroup(jPanel1Layout.createSequentialGroup()
                                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                    .addComponent(removeButton, javax.swing.GroupLayout.DEFAULT_SIZE, 97, Short.MAX_VALUE)
                                    .addComponent(addButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(logoutButton, javax.swing.GroupLayout.DEFAULT_SIZE, 97, Short.MAX_VALUE)
                                    .addComponent(clearCacheButton, javax.swing.GroupLayout.DEFAULT_SIZE, 97, Short.MAX_VALUE)
                                    .addComponent(loginButton, javax.swing.GroupLayout.DEFAULT_SIZE, 97, Short.MAX_VALUE)
                                    .addComponent(clearButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                                .addGap(18, 18, 18)
                                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(scopeSplitPane, javax.swing.GroupLayout.DEFAULT_SIZE, 555, Short.MAX_VALUE)
                                    .addGroup(jPanel1Layout.createSequentialGroup()
                                        .addComponent(jLabel2)
                                        .addGap(0, 0, Short.MAX_VALUE))))
                            .addComponent(jPanel4, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addGroup(jPanel1Layout.createSequentialGroup()
                                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(jPanel6, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(jPanel3, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addGap(0, 0, Short.MAX_VALUE)))))
                .addContainerGap())
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addComponent(helpButton, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(defaultsButton, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addComponent(optionsTitle, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jPanel3, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jPanel4, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jPanel6, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jLabel2)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addComponent(addButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(removeButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(clearButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(loginButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(logoutButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(clearCacheButton)
                        .addGap(1, 1, 1))
                    .addComponent(scopeSplitPane))
                .addGap(6, 6, 6))
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
    }// </editor-fold>//GEN-END:initComponents


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton addButton;
    private javax.swing.JButton clearButton;
    private javax.swing.JButton clearCacheButton;
    private javax.swing.JButton defaultsButton;
    private javax.swing.JLabel errorLabel;
    private javax.swing.JButton helpButton;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JPanel jPanel3;
    private javax.swing.JPanel jPanel4;
    private javax.swing.JPanel jPanel5;
    private javax.swing.JPanel jPanel6;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JButton loginButton;
    private javax.swing.JButton logoutButton;
    private javax.swing.JComboBox<String> modeComboBox;
    private javax.swing.JLabel optionsTitle;
    private javax.swing.JPasswordField passwordField;
    private javax.swing.JButton removeButton;
    private javax.swing.JList<String> scopeList;
    private javax.swing.JSplitPane scopeSplitPane;
    private javax.swing.JTextField urlField;
    private javax.swing.JTextField userDomainField;
    // End of variables declaration//GEN-END:variables
}

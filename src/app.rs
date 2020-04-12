use crate::Id;

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub(crate) struct App {
    pub id: Id,
    pub app_name: String,
    pub extra: String,
    pub name: String,
    pub group: String,
    pub last_touch: String,
    pub password_protected: bool,
    pub favourite: bool,
    pub window_title: String,
    pub window_info: String,
    pub exe_version: String,
    pub autologin: bool,
    pub warn_version: String,
    pub exe_hash: String,
}

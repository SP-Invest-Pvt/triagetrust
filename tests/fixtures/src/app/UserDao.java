package app;

public class UserDao {
    public java.sql.ResultSet find(javax.servlet.http.HttpServletRequest req, java.sql.Connection c) throws Exception {
        String name = req.getParameter("name");
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        return c.createStatement().executeQuery(sql);
    }
}

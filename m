Return-Path: <kasan-dev+bncBAABB54FQKPAMGQE4AQWWLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D1BB668643
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 23:00:25 +0100 (CET)
Received: by mail-qk1-x739.google.com with SMTP id bm30-20020a05620a199e00b006ff813575b1sf14007824qkb.16
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 14:00:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673560824; cv=pass;
        d=google.com; s=arc-20160816;
        b=myqdbZc1D79zg8mE0E7OulVrwjpOzw7RGrqWqmkYf2LUuwrqv69jmoxKEvaz5rlLB/
         cTa5SYMOBW7X8i/YoBiCyM3GTwNjh4KIx+p2IcHZdG6SKoGBX6V/VtObvaZMYfpNBF0o
         VmwgtVmhOZngIrWlY8sClXWyzJK0H9JGoxjU9ZzAmqYg/l6RxJ6llc6rgZQkDczNxiJR
         0R2WNY8UknkCOjOKIBkAOGrfNpwjFgU87YuHhpO+9kAqfuEZGNShPNkTbcwrb4uI6gAr
         sW+afJ3IeilLlaxOWMBhgtNZOOvhi3qwmcovgsuukE5GiPUbYhoa+/dI/ZBxqtixQEGe
         vscA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-subscribe:list-archive:list-help:list-post:list-id
         :mailing-list:precedence:message-id:list-unsubscribe:mime-version
         :subject:to:from:date:sender:dkim-signature;
        bh=sH6btAf1GlUsJO9M4XQQNlfmUzidbema4L3m2wj4XXo=;
        b=jDkjh72iKFggVUEPKH1R6KhGn3KzQkbm8QwQNJw/m/p22QwavI2rne2kbPecKr39kn
         SqhbjldjijHATwMoUmxSM/rLIk00Gona7c9Fg3+zPhm4EMKg+VdsgmQaFMtk2zg3+F4x
         hhqPhaWOOkO29cbP9cjLcXIqvdtx8tTMLq0D3UfNzYfSN87u8ooetRXlSILszoc/WzmL
         65kXiLz8Z9sr+PzhdK5UyIIbVa8FWS63jBF1yvK4ofTH9DClmmPdWaYeFh6zS7YlzeO+
         Pd71T9rJs+uXB9B84nekms0VAWYzFbARX6jjHtfvoQqg0WR4aQSxKxNk87Vz+qCZeVR2
         rY6g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@nw-mbldeal.info header.s=dkim header.b=CkzOjetm;
       spf=pass (google.com: domain of now_on_att-kasan+2ddev=googlegroups.com@nw-mbldeal.info designates 45.13.189.23 as permitted sender) smtp.mailfrom="now_on_att-kasan+2Ddev=googlegroups.com@nw-mbldeal.info";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=nw-mbldeal.info
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-subscribe:list-archive:list-help:list-post:list-id
         :mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:list-unsubscribe:mime-version:subject
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=sH6btAf1GlUsJO9M4XQQNlfmUzidbema4L3m2wj4XXo=;
        b=LJdo/krYdEHck1gzdLIr5FJBLJWZfDMpCF3pwBHkXBD7ZI+gxLuQvi/LAcZMRdfrOO
         86kNIUeoznnS/3AEGB1J9WuJwMbYylHkxBPH0cDSl+ubF/jOlsu1eU7brs0gt43sVSl7
         oMrzbHyOQ4JmpqCej2vdHfAji5Pqrer/Jrp/Sn/27T93UksWshXgC+zDSqBOOxgQnRo9
         orwxOJXCgLNYNgvcdvqL47pgf75eLs4ypSKHxVR0Yh1ux6u6XkPI2J7Kr+MDpWCiVuzX
         DnBUNlGJhXIdXmGrhuUZbGLtctUx4ENYdvb2z/KEHqdD2HNQRCY+Q6zgkprvrBsu8RwL
         W1xw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :list-unsubscribe:mime-version:subject:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=sH6btAf1GlUsJO9M4XQQNlfmUzidbema4L3m2wj4XXo=;
        b=0OHxj6f+LnsPT864/QvpLuPYB0KeN6SkME82jlxnhIeZGWMfdcYr6ECUsdiiFTFCQI
         GsxmyEpLBaTc9mUAx2dkpNuelXqwaFM/K9ktwHLgxmF9kT/KD5HOtPBAxNe2gPwKMf9w
         EMf7/lIHIOmvmqeOHf+R47gUkBbhlqz0HiiXtMUqJhWXE8xgGz31ix2dpc3fu0X7IF3Z
         ag9dVBga91kVOtHBSnXMVUiQP+7bqczgMj2bcbBPv0aoQ0bjzYhDpU+sTh/o3W+vcsx4
         MraFmal4nmrvsG9fwBqTdOx9mowp5z2f1uZ3F9LMJv0rvN9CO+8W+/+A68Nyb/72U4Nx
         xBMw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kqIPvg38Ky7eCW3CtEj65t5sijRvLlV85+SbBwAddOjHJqLAO35
	jTHUoRd4XD2NPDMnpeJIJPY=
X-Google-Smtp-Source: AMrXdXtgDT/mrMtok4Dc+v4cCCxn3XlvQK39x4CLNhOJsSE5GZgj1CtELCHrQQdjsoy0HGa1lxtc8w==
X-Received: by 2002:ac8:7647:0:b0:3b2:2210:47c9 with SMTP id i7-20020ac87647000000b003b2221047c9mr138672qtr.443.1673560823585;
        Thu, 12 Jan 2023 14:00:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:ab58:0:b0:531:d0e0:dbaa with SMTP id i24-20020a0cab58000000b00531d0e0dbaals1933723qvb.7.-pod-prod-gmail;
 Thu, 12 Jan 2023 14:00:17 -0800 (PST)
X-Received: by 2002:a0c:8067:0:b0:4c6:f5e2:f13a with SMTP id 94-20020a0c8067000000b004c6f5e2f13amr108614282qva.37.1673560817048;
        Thu, 12 Jan 2023 14:00:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673560817; cv=none;
        d=google.com; s=arc-20160816;
        b=UxS+B42bi94eTu0KHane+NELQkBXKExfTKLX/0HXnzCqzdsqc1GikoLChp40M4bU1O
         xszL1SCG3FbfKrAyufwplfdv1jzvWvUXvl4YedHD09FEN531zsQZct1eRM2DqGd9e0fG
         vNxeoILQvkeRaWQ9TU0KiI1WPsnKfZZuzFwJrMzGybZWiwzVJNnX9JTBF6Y44b0Tx6Hu
         /K/6NVPJVeJyKTgRUpZphpk+BTdYav0K5SzrWd2ZWczzFkxtvjhdeo4q0Fjz2tc/p5eq
         DAU071Hw8Ic1ACSVmeg5T2n+dZRPPsjNsTvgNZw72bHtLU7PX3Hcy1IFyeHJUMykUk9O
         Wnww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:list-unsubscribe:mime-version:subject:to:from:date
         :domainkey-signature:dkim-signature;
        bh=kS329KGZKEoXVihJVVrj06Q3Ogx/vkqCPEs+LusbDqo=;
        b=m2hOkMUcSarocWU2hsQ9393o/7lnNVhOfHsnJuEnheb+kOBm/kGeWkBUuqZQcXuyND
         2sv34vAaHvoNYaMz+qd47RC5rH8nNlSE9Z7ps0GmbS5kraqxmSCPzLL0C8agxYJ3Uh+a
         V5RTAA9BaFp0JAL4JjL6rjxHqRpSsSJGyeWwC46uTkRBaPSaMHIbOsEUBp8wPhb3XToo
         4jQMvc/mvrrzLseXK4jvcfuY4aOU32iOkWMyaTI9gCwi85rmz4I1BoNe2kcn/yZ/z13H
         ZMKR5t5RPZfqVZCVF3SgnzIUPRyUKZ91zdHy3Rk/QgVgwUq5xH2DtjNsbgcBV2DLDTgE
         6WRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@nw-mbldeal.info header.s=dkim header.b=CkzOjetm;
       spf=pass (google.com: domain of now_on_att-kasan+2ddev=googlegroups.com@nw-mbldeal.info designates 45.13.189.23 as permitted sender) smtp.mailfrom="now_on_att-kasan+2Ddev=googlegroups.com@nw-mbldeal.info";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=nw-mbldeal.info
Received: from mail.nw-mbldeal.info ([45.13.189.23])
        by gmr-mx.google.com with ESMTP id x11-20020ae9e64b000000b00705bf2df50bsi716108qkl.0.2023.01.12.14.00.16
        for <kasan-dev@googlegroups.com>;
        Thu, 12 Jan 2023 14:00:17 -0800 (PST)
Received-SPF: pass (google.com: domain of now_on_att-kasan+2ddev=googlegroups.com@nw-mbldeal.info designates 45.13.189.23 as permitted sender) client-ip=45.13.189.23;
Received: by mail.nw-mbldeal.info id ho21f00001gk for <kasan-dev@googlegroups.com>; Thu, 12 Jan 2023 16:54:58 -0500 (envelope-from <now_on_att-kasan+2Ddev=googlegroups.com@nw-mbldeal.info>)
Date: Thu, 12 Jan 2023 16:54:58 -0500
From: "Now On ATT" <now_on_att@nw-mbldeal.info>
To: <kasan-dev@googlegroups.com>
Subject: AT&T reward is just a few clicks away - While supplies last
MIME-Version: 1.0
Content-Type: multipart/alternative; 
	boundary="----=_Part_757_1561506108.1673560469070"
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>
Message-ID: <0.0.0.54.1D926D083C13950.5BC4E3@mail.nw-mbldeal.info>
X-Original-Sender: now_on_att@nw-mbldeal.info
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@nw-mbldeal.info header.s=dkim header.b=CkzOjetm;       spf=pass
 (google.com: domain of now_on_att-kasan+2ddev=googlegroups.com@nw-mbldeal.info
 designates 45.13.189.23 as permitted sender) smtp.mailfrom="now_on_att-kasan+2Ddev=googlegroups.com@nw-mbldeal.info";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=nw-mbldeal.info
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>

------=_Part_757_1561506108.1673560469070
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.=
w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns=3D"http://www.w3.org/1999/xhtml">
 <head>=20
  <title>WHAT YOU THINK!</title>=20
  <meta content=3D"text/html; charset=3Dutf-8" http-equiv=3D"Content-Type" =
/>=20
  <meta content=3D"IE=3Dedge" http-equiv=3D"X-UA-Compatible" />=20
  <meta content=3D"width=3Ddevice-width, initial-scale=3D1.0 " name=3D"view=
port" />=20
  <meta content=3D"telephone=3Dno" name=3D"format-detection" />
  <!--[if !mso]><!-->=20
  <link href=3D"http://www.nw-mbldeal.info/Japanized-knots/c9c5r239i5z8B6y1=
2UN4638T10c9Z27KgDwDr-HI5fZssZhIZvs4twEGsi7VQ0dRQK7tO10sHZ6APJwD@" rel=3D"s=
tylesheet" />
  <!--<![endif]-->=20
  <style type=3D"text/css">body {
      -webkit-text-size-adjust: 100% !important;
      -ms-text-size-adjust: 100% !important;
      -webkit-font-smoothing: antialiased !important;
      }
      img {
      border: 0 !important;
      outline: none !important;
      }
      p {
      Margin: 0px !important;
      Padding: 0px !important;
      }
      table {
      border-collapse: collapse;
      mso-table-lspace: 0px;
      mso-table-rspace: 0px;
      }
      td, a, span {
      border-collapse: collapse;
      mso-line-height-rule: exactly;
      }
      .ExternalClass * {
      line-height: 100%;
      }
      span.MsoHyperlink {
      mso-style-priority:99;
      color:inherit;}
      span.MsoHyperlinkFollowed {
      mso-style-priority:99;
      color:inherit;}
	</style>=20
  <style media=3D"only screen and (min-width:481px) and (max-width:599px)" =
type=3D"text/css">@media only screen and (min-width:481px) and (max-width:5=
99px) {
      table[class=3Dem_main_table] {
      width: 100% !important;
      }
      table[class=3Dem_wrapper] {
      width: 100% !important;
      }
      td[class=3Dem_hide], br[class=3Dem_hide] {
      display: none !important;
      }
      img[class=3Dem_full_img] {
      width: 100% !important;
      height: auto !important;
      }
      td[class=3Dem_align_cent] {
      text-align: center !important;
      }
      td[class=3Dem_aside]{
      padding-left:10px !important;
      padding-right:10px !important;
      }
      td[class=3Dem_height]{
      height: 20px !important;
      }
      td[class=3Dem_space]{
      width:10px !important;=09
      }
      td[class=3Dem_font]{
      font-size:14px !important;=09
      }
      td[class=3Dem_align_cent1] {
      text-align: center !important;
      padding-bottom: 10px !important;
      }
      }
	</style>=20
  <style media=3D"only screen and (max-width:480px)" type=3D"text/css">@med=
ia only screen and (max-width:480px) {
      table[class=3Dem_main_table] {
      width: 100% !important;
      }
      table[class=3Dem_wrapper] {
      width: 100% !important;
      }
      td[class=3Dem_hide], br[class=3Dem_hide], span[class=3Dem_hide] {
      display: none !important;
      }
      img[class=3Dem_full_img] {
      width: 100% !important;
      height: auto !important;
      }
      td[class=3Dem_align_cent] {
      text-align: center !important;
      }
      td[class=3Dem_height]{
      height: 20px !important;
      }
      td[class=3Dem_aside]{
      padding-left:10px !important;
      padding-right:10px !important;
      }=20
      td[class=3Dem_font]{
      font-size:14px !important;
      line-height:28px !important;
      }
      td[class=3Dem_space]{
      width:10px !important;=09
      }
      span[class=3Dem_br]{
      display:block !important;
      }
      td[class=3Dem_align_cent1] {
      text-align: center !important;
      padding-bottom: 10px !important;
      }
      }
	</style>=20
 </head>=20
 <body bgcolor=3D"#ffffff" style=3D"margin:0px; padding:0px;">=20
  <table bgcolor=3D"#ffffff" border=3D"0" cellpadding=3D"0" cellspacing=3D"=
0" width=3D"100%">
   <!-- =3D=3D=3D PRE HEADER SECTION=3D=3D=3D -->=20
   <tbody>=20
    <tr>=20
     <td align=3D"center" bgcolor=3D"#30373b" valign=3D"top">=20
      <table align=3D"center" border=3D"0" cellpadding=3D"0" cellspacing=3D=
"0" class=3D"em_main_table" style=3D"table-layout:fixed;" width=3D"600">=20
       <tbody>=20
        <tr>=20
         <td bgcolor=3D"#30373b" class=3D"em_hide" style=3D"line-height:0px=
; font-size:0px;" width=3D"600">&nbsp;</td>=20
        </tr>=20
        <tr>=20
         <td valign=3D"top">=20
          <table align=3D"center" border=3D"0" cellpadding=3D"0" cellspacin=
g=3D"0" class=3D"em_wrapper" width=3D"600">=20
           <tbody>=20
            <tr>=20
             <td class=3D"em_height" height=3D"10" style=3D"font-size:1px; =
line-height:1px;">&nbsp;</td>=20
            </tr>=20
            <tr>=20
             <td valign=3D"top">=20
              <table border=3D"0" cellpadding=3D"0" cellspacing=3D"0" width=
=3D"100%">=20
               <tbody>=20
                <tr>=20
                 <td valign=3D"top">=20
                  <table align=3D"right" border=3D"0" cellpadding=3D"0" cel=
lspacing=3D"0" class=3D"em_wrapper" width=3D"150">=20
                   <tbody>=20
                    <tr>=20
                     <td align=3D"right" class=3D"em_align_cent1" style=3D"=
font-family:'Open Sans', Arial, sans-serif; font-size:12px; line-height:16p=
x; color:#848789; text-decoration:underline;">&nbsp;</td>=20
                    </tr>=20
                   </tbody>=20
                  </table>=20
                  <table align=3D"left" border=3D"0" cellpadding=3D"0" cell=
spacing=3D"0" class=3D"em_wrapper" width=3D"400">=20
                   <tbody>=20
                    <tr>=20
                     <td align=3D"left" class=3D"em_align_cent" style=3D"fo=
nt-family:'Open Sans', Arial, sans-serif; font-size:12px; line-height:18px;=
 color:#848789; text-decoration:none;">&nbsp;</td>=20
                    </tr>=20
                   </tbody>=20
                  </table> </td>=20
                </tr>=20
               </tbody>=20
              </table> </td>=20
            </tr>=20
            <tr>=20
             <td class=3D"em_height" height=3D"10" style=3D"font-size:1px; =
line-height:1px;">&nbsp;</td>=20
            </tr>=20
           </tbody>=20
          </table> </td>=20
        </tr>=20
       </tbody>=20
      </table> </td>=20
    </tr>=20
    <!-- =3D=3D=3D //PRE HEADER SECTION=3D=3D=3D -->=20
    <tr>=20
     <td align=3D"center" bgcolor=3D"#ffffff" valign=3D"top">=20
      <table align=3D"center" border=3D"0" cellpadding=3D"0" cellspacing=3D=
"0" class=3D"em_main_table" style=3D"table-layout:fixed;" width=3D"600">
       <!-- =3D=3D=3D LOGO SECTION =3D=3D=3D -->=20
       <tbody>=20
        <tr>=20
         <td class=3D"em_height" height=3D"40">&nbsp;</td>=20
        </tr>=20
        <tr>=20
         <td align=3D"center">=20
          <fieldset style=3D"border-style: solid; border-bottom: none; bord=
er-left: none; border-right: none">
           <legend style=3D"padding: 15px; font-family: Gotham, 'Helvetica =
Neue', Helvetica, Arial, 'sans-serif'; font-size: 38px; color: #027CD5"><b>=
AT&amp;T</b></legend>
          </fieldset> </td>=20
        </tr>=20
        <tr>=20
         <td class=3D"em_height" height=3D"30">&nbsp;</td>=20
        </tr>=20
        <!-- =3D=3D=3D //LOGO SECTION =3D=3D=3D -->
        <!-- =3D=3D=3D NEVIGATION SECTION =3D=3D=3D -->=20
        <tr>=20
         <td bgcolor=3D"#fed69c" height=3D"1" style=3D"font-size:0px; line-=
height:0px;">&nbsp;</td>=20
        </tr>=20
        <tr>=20
         <td height=3D"14" style=3D"font-size:1px; line-height:1px;">&nbsp;=
</td>=20
        </tr>=20
        <tr>=20
         <td align=3D"center" class=3D"em_font" style=3D"font-family:'Open =
Sans', Arial, sans-serif; font-size:15px; line-height:18px; color:#30373b; =
text-transform:uppercase; font-weight:bold;"><a href=3D"http://www.nw-mblde=
al.info/productive-torturer/c245y239F5QK8z612GJ4639K10c9Q27SgDwDr-HI5fZssZh=
IZvs4twEGsi7fQ0dRQK5NK10Z6pTjwDW" style=3D"text-decoration:none; color:#303=
73b;" target=3D"_blank">Deals</a> &nbsp;&nbsp;&nbsp;&nbsp;|&nbsp;&nbsp;&nbs=
p;&nbsp; <a href=3D"http://www.nw-mbldeal.info/productive-torturer/c245y239=
F5QK8z612GJ4639K10c9Q27SgDwDr-HI5fZssZhIZvs4twEGsi7fQ0dRQK5NK10Z6pTjwDW" st=
yle=3D"text-decoration:none; color:#30373b;" target=3D"_blank">Phone &amp; =
Devices</a><span class=3D"em_hide"> &nbsp;&nbsp;&nbsp;&nbsp;|&nbsp;&nbsp;&n=
bsp;&nbsp; </span><a href=3D"http://www.nw-mbldeal.info/productive-torturer=
/c245y239F5QK8z612GJ4639K10c9Q27SgDwDr-HI5fZssZhIZvs4twEGsi7fQ0dRQK5NK10Z6p=
TjwDW" style=3D"text-decoration:none; color:#30373b;" target=3D"_blank">Wir=
eless</a> &nbsp;&nbsp;&nbsp;&nbsp;|&nbsp;&nbsp;&nbsp;&nbsp; <a href=3D"http=
://www.nw-mbldeal.info/productive-torturer/c245y239F5QK8z612GJ4639K10c9Q27S=
gDwDr-HI5fZssZhIZvs4twEGsi7fQ0dRQK5NK10Z6pTjwDW" style=3D"text-decoration:n=
one; color:#30373b;" target=3D"_blank">Internet</a></td>=20
        </tr>=20
        <tr>=20
         <td height=3D"14" style=3D"font-size:1px; line-height:1px;">&nbsp;=
</td>=20
        </tr>=20
        <tr>=20
         <td bgcolor=3D"#fed69c" height=3D"1" style=3D"font-size:0px; line-=
height:0px;">&nbsp;</td>=20
        </tr>=20
        <!-- =3D=3D=3D //NEVIGATION SECTION =3D=3D=3D -->
        <!-- =3D=3D=3D RATE OUR SERVICE SECTION =3D=3D=3D -->=20
        <tr>=20
         <td class=3D"em_aside" valign=3D"top">=20
          <table border=3D"0" cellpadding=3D"0" cellspacing=3D"0" width=3D"=
100%">=20
           <tbody>=20
            <tr>=20
             <td class=3D"em_height" height=3D"36">&nbsp;</td>=20
            </tr>=20
            <tr>=20
             <td align=3D"center" style=3D"font-family:'Open Sans', Arial, =
sans-serif; font-size:28px; font-weight:bold; line-height:20px; text-transf=
orm:uppercase; color:#129DDC;"><a href=3D"http://www.nw-mbldeal.info/produc=
tive-torturer/c245y239F5QK8z612GJ4639K10c9Q27SgDwDr-HI5fZssZhIZvs4twEGsi7fQ=
0dRQK5NK10Z6pTjwDW"><img alt=3D"" src=3D"http://www.nw-mbldeal.info/8v96aL2=
3U95vK7ra12g4L63bh10c9S27kgDwDr-HI5fZssZhIZvs4twEGsi7NQ0dRQK6Sn1NM06klwpXD/=
Japanized-knots" width=3D"100%" /></a><br /> <br /> The AT&amp;T difference=
<br /> &nbsp;</td>=20
            </tr>=20
            <tr>=20
             <td align=3D"center" style=3D"font-family:'Open Sans', Arial, =
sans-serif; font-size:25px; line-height:normal; color:#999999;">Get just a =
few clicks away from The <b>$100 AT&amp;T Card</b>, by completing our 20-Se=
cond Service Survey about your recent experience with us.</td>=20
            </tr>=20
            <tr>=20
             <td height=3D"16" style=3D"font-size:1px; line-height:1px;">&n=
bsp;</td>=20
            </tr>=20
            <tr>=20
             <td align=3D"center">&nbsp;</td>=20
            </tr>=20
            <tr>=20
             <td align=3D"center" class=3D"em_height" height=3D"41">=20
              <table align=3D"center" border=3D"0" cellpadding=3D"0" cellsp=
acing=3D"0">=20
               <tbody>=20
                <tr>=20
                 <td align=3D"center" bgcolor=3D"" style=3D"border-radius:3=
px;color:#8999ca;cursor:auto;" valign=3D"middle"><a href=3D"http://www.nw-m=
bldeal.info/productive-torturer/c245y239F5QK8z612GJ4639K10c9Q27SgDwDr-HI5fZ=
ssZhIZvs4twEGsi7fQ0dRQK5NK10Z6pTjwDW" style=3D"display:inline-block;text-de=
coration:none;background:none;border:solid #8999ca;border-radius:3px;color:=
#8999ca;font-family:Helvetica;font-size:23px;font-weight:bold;padding:10px =
25px;margin:0px;" target=3D"_blank">Go And Start Now </a></td>=20
                </tr>=20
               </tbody>=20
              </table> <br /> &nbsp;</td>=20
            </tr>=20
            <tr>=20
             <td align=3D"center" valign=3D"top">=20
              <table border=3D"0" cellpadding=3D"0" cellspacing=3D"0" width=
=3D"100%">=20
               <tbody>=20
                <tr>=20
                 <td bgcolor=3D"#129DDC" width=3D"1">&nbsp;</td>=20
                 <td align=3D"center" valign=3D"top">=20
                  <table align=3D"center" border=3D"0" cellpadding=3D"0" ce=
llspacing=3D"0" width=3D"100%">=20
                   <tbody>=20
                    <tr>=20
                     <td bgcolor=3D"#129DDC" height=3D"1" style=3D"line-hei=
ght:0px; font-size:0px;">&nbsp;</td>=20
                    </tr>=20
                    <tr>=20
                     <td class=3D"em_height" height=3D"36">&nbsp;</td>=20
                    </tr>=20
                    <tr>=20
                     <td align=3D"center" style=3D"font-family:'Open Sans',=
 Arial, sans-serif; font-size:18px; font-weight:bold; line-height:20px; tex=
t-transform:uppercase; color:#129DDC;"><a href=3D"http://www.nw-mbldeal.inf=
o/productive-torturer/c245y239F5QK8z612GJ4639K10c9Q27SgDwDr-HI5fZssZhIZvs4t=
wEGsi7fQ0dRQK5NK10Z6pTjwDW" style=3D"color:#129DDC; text-decoration:none;" =
target=3D"_blank">Click to rate our services</a></td>=20
                    </tr>=20
                    <tr>=20
                     <td height=3D"18" style=3D"font-size:1px; line-height:=
1px;">&nbsp;</td>=20
                    </tr>=20
                    <tr>=20
                     <td align=3D"center" valign=3D"top">=20
                      <table align=3D"center" border=3D"0" cellpadding=3D"0=
" cellspacing=3D"0" class=3D"em_wrapper" style=3D"max-width:400px;" width=
=3D"400">=20
                       <tbody>=20
                        <tr>=20
                         <td width=3D"9">&nbsp;</td>=20
                         <td align=3D"center" bgcolor=3D"#129DDC" height=3D=
"45" style=3D"font-family:'Open Sans', Arial, sans-serif; font-size:17px; f=
ont-weight:bold; color:#ffffff;" width=3D"45"><a href=3D"http://www.nw-mbld=
eal.info/productive-torturer/c245y239F5QK8z612GJ4639K10c9Q27SgDwDr-HI5fZssZ=
hIZvs4twEGsi7fQ0dRQK5NK10Z6pTjwDW" style=3D"color:#ffffff; text-decoration:=
none;" target=3D"_blank">1</a></td>=20
                         <td class=3D"em_space" width=3D"39">&nbsp;</td>=20
                         <td align=3D"center" bgcolor=3D"#129DDC" height=3D=
"45" style=3D"font-family:'Open Sans', Arial, sans-serif; font-size:17px; f=
ont-weight:bold; color:#ffffff;" width=3D"45"><a href=3D"http://www.nw-mbld=
eal.info/productive-torturer/c245y239F5QK8z612GJ4639K10c9Q27SgDwDr-HI5fZssZ=
hIZvs4twEGsi7fQ0dRQK5NK10Z6pTjwDW" style=3D"color:#ffffff; text-decoration:=
none;" target=3D"_blank">2</a></td>=20
                         <td class=3D"em_space" width=3D"39">&nbsp;</td>=20
                         <td align=3D"center" bgcolor=3D"#129DDC" height=3D=
"45" style=3D"font-family:'Open Sans', Arial, sans-serif; font-size:17px; f=
ont-weight:bold; color:#ffffff;" width=3D"45"><a href=3D"http://www.nw-mbld=
eal.info/productive-torturer/c245y239F5QK8z612GJ4639K10c9Q27SgDwDr-HI5fZssZ=
hIZvs4twEGsi7fQ0dRQK5NK10Z6pTjwDW" style=3D"color:#ffffff; text-decoration:=
none;" target=3D"_blank">3</a></td>=20
                         <td class=3D"em_space" width=3D"39">&nbsp;</td>=20
                         <td align=3D"center" bgcolor=3D"#129DDC" height=3D=
"45" style=3D"font-family:'Open Sans', Arial, sans-serif; font-size:17px; f=
ont-weight:bold; color:#ffffff;" width=3D"45"><a href=3D"http://www.nw-mbld=
eal.info/productive-torturer/c245y239F5QK8z612GJ4639K10c9Q27SgDwDr-HI5fZssZ=
hIZvs4twEGsi7fQ0dRQK5NK10Z6pTjwDW" style=3D"color:#ffffff; text-decoration:=
none;" target=3D"_blank">4</a></td>=20
                         <td class=3D"em_space" width=3D"39">&nbsp;</td>=20
                         <td align=3D"center" bgcolor=3D"#129DDC" height=3D=
"45" style=3D"font-family:'Open Sans', Arial, sans-serif; font-size:17px; f=
ont-weight:bold; color:#ffffff;" width=3D"45"><a href=3D"http://www.nw-mbld=
eal.info/productive-torturer/c245y239F5QK8z612GJ4639K10c9Q27SgDwDr-HI5fZssZ=
hIZvs4twEGsi7fQ0dRQK5NK10Z6pTjwDW" style=3D"color:#ffffff; text-decoration:=
none;" target=3D"_blank">5</a></td>=20
                         <td width=3D"10">&nbsp;</td>=20
                        </tr>=20
                       </tbody>=20
                      </table> </td>=20
                    </tr>=20
                    <tr>=20
                     <td class=3D"em_height" height=3D"36">&nbsp;</td>=20
                    </tr>=20
                    <tr>=20
                     <td bgcolor=3D"#129DDC" height=3D"1" style=3D"line-hei=
ght:0px; font-size:0px;">&nbsp;</td>=20
                    </tr>=20
                   </tbody>=20
                  </table> </td>=20
                 <td bgcolor=3D"#129DDC" width=3D"1">&nbsp;</td>=20
                </tr>=20
               </tbody>=20
              </table> </td>=20
            </tr>=20
            <tr>=20
             <td bgcolor=3D"#d8e4f0" height=3D"1" style=3D"font-size:0px;li=
ne-height:0px;">&nbsp;</td>=20
            </tr>=20
            <tr>=20
             <td class=3D"em_height" height=3D"35">&nbsp;</td>=20
            </tr>=20
            <tr>=20
             <td class=3D"em_height" height=3D"31">&nbsp;</td>=20
            </tr>=20
           </tbody>=20
          </table> </td>=20
        </tr>=20
        <!-- =3D=3D=3D RATE OUR SERVICE SECTION =3D=3D=3D -->=20
       </tbody>=20
      </table> </td>=20
    </tr>=20
    <!-- =3D=3D=3D FOOTER SECTION =3D=3D=3D -->=20
    <tr>=20
     <td align=3D"center" bgcolor=3D"#30373b" class=3D"em_aside" valign=3D"=
top">=20
      <table align=3D"center" border=3D"0" cellpadding=3D"0" cellspacing=3D=
"0" class=3D"em_main_table" style=3D"table-layout:fixed;" width=3D"600">=20
       <tbody>=20
        <tr>=20
         <td class=3D"em_height" height=3D"35">&nbsp;</td>=20
        </tr>=20
        <tr>=20
         <td align=3D"center" valign=3D"top">=20
          <table align=3D"center" border=3D"0" cellpadding=3D"0" cellspacin=
g=3D"0">=20
           <tbody>=20
            <tr>=20
             <td valign=3D"top">&nbsp;</td>=20
             <td width=3D"7">&nbsp;</td>=20
             <td valign=3D"top">&nbsp;</td>=20
             <td width=3D"7">&nbsp;</td>=20
             <td valign=3D"top">&nbsp;</td>=20
             <td width=3D"7">&nbsp;</td>=20
             <td valign=3D"top">&nbsp;</td>=20
             <td width=3D"7">&nbsp;</td>=20
             <td valign=3D"top">&nbsp;</td>=20
             <td width=3D"7">&nbsp;</td>=20
             <td valign=3D"top">&nbsp;</td>=20
            </tr>=20
           </tbody>=20
          </table> </td>=20
        </tr>=20
        <tr>=20
         <td class=3D"em_height" height=3D"22">&nbsp;</td>=20
        </tr>=20
        <tr>=20
         <td align=3D"center" style=3D"font-family:'Open Sans', Arial, sans=
-serif; font-size:12px; line-height:18px; color:#848789;"><span style=3D"te=
xt-decoration: none; ">No longer want to receive email from us?,</span><a h=
ref=3D"http://www.nw-mbldeal.info/be76p23Iq95OPK8612u463NaB10c9g27JgDwDr-HI=
5fZssZhIZvs4twEGsi7HQ0dRQK5U10op5QyTwD/pairings-Fruehauf" style=3D"text-dec=
oration-line: none;"> <span style=3D"color: red">Go-Right-Here </span> </a>=
<br /> 126 E 23rd St New York, NY, US 10010<br /> <br /> <br /> <br /> <br =
/> <br /> <style><style><span></span></style><big></big><span id=3D"rearran=
gement"></span></style><style class=3D"collide"><font><font size=3D"mustach=
es"></font></style><span size=3D"skylarks"></span><style></style></font><fo=
nt color=3D"Wainwright"></font></td>=20
        </tr>=20
        <tr>=20
         <td height=3D"10" style=3D"font-size:1px; line-height:1px;">&nbsp;=
</td>=20
        </tr>=20
        <tr>=20
         <td align=3D"center" style=3D"font-family:'Open Sans', Arial, sans=
-serif; font-size:12px; line-height:18px; color:#848789;text-transform:uppe=
rcase;">&nbsp;</td>=20
        </tr>=20
        <tr>=20
         <td height=3D"10" style=3D"font-size:1px; line-height:1px;">&nbsp;=
</td>=20
        </tr>=20
        <tr>=20
         <td align=3D"center" style=3D"font-family:'Open Sans', Arial, sans=
-serif; font-size:12px; line-height:18px; color:#848789;text-transform:uppe=
rcase;">&nbsp;</td>=20
        </tr>=20
        <tr>=20
         <td class=3D"em_height" height=3D"35">&nbsp;</td>=20
        </tr>=20
       </tbody>=20
      </table> </td>=20
    </tr>=20
    <!-- =3D=3D=3D //FOOTER SECTION =3D=3D=3D -->=20
   </tbody>=20
  </table>=20
  <div style=3D"display:none; white-space:nowrap; font:20px courier; color:=
#ffffff; background-color:#ffffff;">
   &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &n=
bsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;
  </div>  =20
 <img src=3D"http://www.nw-mbldeal.info/4df6F23S9F5Vwl8512Q463cNK10c9H27YgD=
wDr-HI5fZssZhIZvs4twEGsi7dQ0dRQK6l1vs0z5nUqwD/Japanized-knots" alt=3D""/></=
body>
</html>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/0.0.0.54.1D926D083C13950.5BC4E3%40mail.nw-mbldeal.info=
?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/=
kasan-dev/0.0.0.54.1D926D083C13950.5BC4E3%40mail.nw-mbldeal.info</a>.<br />

------=_Part_757_1561506108.1673560469070--


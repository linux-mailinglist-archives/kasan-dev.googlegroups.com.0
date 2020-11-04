Return-Path: <kasan-dev+bncBAABBKE7RP6QKGQERLYAQCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8AC172A68E3
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Nov 2020 16:58:33 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id r19sf8545837ljj.9
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 07:58:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604505513; cv=pass;
        d=google.com; s=arc-20160816;
        b=v+agNiTZhCRlIIJ19Rd0ChfLEcqV1ug0boCCjdqA2G/21dYMJOO//urE19P1x6cuXz
         QLLhhIUccKLGzTwZpByMTnvagB0GNDe9GSDb1JzXYR4K/uc7+2Yx1X9/hOeh6vEYw/0h
         KyksGAJaZIZRhlD2X1cSZT/+n216Do0C3rQLHEnqb5mwa9YdY4LZ+/H2xpIU+CeHAbut
         dgv8q+pKASWVcg5R+2VuB7Fo2vYrN3qaY6+Mf+AFGfsIQLdKkUxSWFPYSnxH3Btx/7Dw
         8IA3ijJdxPlkV/aBJQA7ZR7Ivk+C94SF3NOT4WzbDIXgJy2jNE+GmVU4HnsMInpaN74e
         278Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:reply-to:date
         :mime-version:subject:to:from:dkim-signature;
        bh=K2xln8irtnWktVz69WQ8XT9dMoSu6A5dSnJJPGpzqZk=;
        b=jX2r3Den2fMYQEf8aZlhGrqFXQ2gnZ9ZWenmAxbJut45kjA5OwmY9VACi4f45eQRg3
         2mhdAFMj3NIYVeVO8BE5FWYZI4YNXO+onPBZ6yZO7IN5ewS7QoxgnTZgaE6o11QP6qHw
         mWmtE9U0X3JPF6lljlhYn5WhwKHvLBiz5Gs29G2syONrkyMfO1TFDLd+TfhWJtVUEqK/
         7ZmYbGAGMOJCYvLcW8LMrIgTPb5Tfvt2cXKSgaIsNpnsH+rSOtLbHIIel3CWs/2LPL7F
         n/kAkC2cragP9H+FSMOeoI0DODSRZcFFZtLuZuDdtEDDhKlBDbXuFKO8Tv45/QbemmIk
         7o7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mail.ru header.s=mail3 header.b="FdZ4G/uq";
       spf=pass (google.com: domain of kartikr226l0oh2@mail.ru designates 217.69.138.180 as permitted sender) smtp.mailfrom=kartikr226l0oh2@mail.ru;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=mail.ru
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=from:to:subject:mime-version:date:reply-to:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=K2xln8irtnWktVz69WQ8XT9dMoSu6A5dSnJJPGpzqZk=;
        b=TEstYg3tZpry9GxlT0pv/A0x4TH8ueX4MFqTpMJ6o8amYtriAzW3vLrFgIwga9kYRf
         wNmjBCY+o5ogdxSbce7cQUMrCX9hpDIvEhNj19tOuuPtDsXT+lOLRlxD85eWruT8GMmx
         PBOxcjaapHgV0hOJk48/rhNje9kHG5iYE14ofdEwYr2gFIl2npOrysUZoOy2wGZKPdcj
         AH+42k86cSYTxYV4Dg5nPqyjVlwrmzzRIxm/HNgwWJ6+xihFYt7aWU1hQuAX7Dvk5HEQ
         Wray0q3MjrvS5l48XaAgROZWT/uLG86ULVVYa6TTdcaJ4kMKP/Ui/segYezZGvnZKYAL
         L+ng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:from:to:subject:mime-version:date:reply-to
         :message-id:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=K2xln8irtnWktVz69WQ8XT9dMoSu6A5dSnJJPGpzqZk=;
        b=L6N/o/YNUSezmXOmThjkkk7L3LAisILG0XiFqVOAu6+uNqvUXk/LAnMk6BYKVl5mM8
         Icwyl56kwx/AXa3v8zRyWQooPtYD+9PyxXloq0yUkPk4mihzwiWghMXNTkqDvENdQdYl
         CTOhbb+EIOLz0O9P0wVAHTy2gLov8QfjizoaV3c+qqvxVY+oBktgWY5SOxDj+GXdk2aa
         2qE03lDBlRBxYJkhPf/QJg7WlCRbJVO4O5Et51GKcGyAQ/GLaQ/jyGfA0gGNPTeoeCnj
         zQZ/+JadgE/iogzUNymSmlZPcVv+pIT5vKY4lDG8AFiK/nO/d3WrVpOyPtxy4rVG3Bkl
         KSWw==
X-Gm-Message-State: AOAM5314RuigUsLPDsM0Z22c36gfs+MDb1TOiVJBCPG6v5Lurfgf+bfW
	5lJmSRFfwsdB6OH9B3bcJTA=
X-Google-Smtp-Source: ABdhPJyQEMcP1eNG2kXsnX2UjdPARGfNXgpE+zijJJ6edKBF4QxFtwU90aRDEAQ3QBn1mm2wbjQ4Pw==
X-Received: by 2002:a2e:9bc5:: with SMTP id w5mr9045821ljj.238.1604505513127;
        Wed, 04 Nov 2020 07:58:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b016:: with SMTP id y22ls491261ljk.3.gmail; Wed, 04 Nov
 2020 07:58:32 -0800 (PST)
X-Received: by 2002:a05:651c:3db:: with SMTP id f27mr8800518ljp.270.1604505512243;
        Wed, 04 Nov 2020 07:58:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604505512; cv=none;
        d=google.com; s=arc-20160816;
        b=Q4kl4f2R8A6cQehB3HBOPvjRuAYefRAH90VMSH8pJUc70WjVj6ScYaM3BiR+n+s220
         SpqXP4Ipl5M9P3ettE1O6WXfJKcuMyRSOtheMfkY4wrgq0+WFEPOOnhiIVfpcUYSYU7t
         6VMMFPnGWmzPHswrfFC8AbCWKxl7kFaZjlO/7hmaAoE36IPPuwJUp3jF+MgLCYdA6NaR
         XlBOgVWlhS6JBZvZbgDvchWQOG/U7RuyPigRttzqKMFDs9ntaKydGr+OzK4IWqmsj3q6
         dTecrMF+/2jy/LZvOE3zkXVmjo7sg2EPdyPvrvbTVM9fpA7NPxRIw2uGqCHtz8+6kMT9
         Vc2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:reply-to:date:mime-version:subject:to:from
         :dkim-signature;
        bh=trPF6bh5p5r5jDwKMvr2GSVvXk8tQtmr87rh57iSGNA=;
        b=vFPcLbgQbHCDB1oXdhHwAvNHe9QiyllM84YUvzw68OvKP7Xvq3XiM1anPRviercUZO
         /2U1EsxyFrRdfRzBYPMCje2yVzOELf0+iBIk4xIRw3QNXHDyDXdi/JiFThe7GRH1/33Y
         afdetkX3XJNA8aKImk+oOjJPxdltL5EDJKcP4mnvcFdhFdUO/odgVTmJqNkrPk0P+Pn9
         JJutHt+Vg/Tzb7rBFj9zuyaNr860CJ7uSj1xPju8so0C0ua5f5taS2jldp9MkbK+ttd6
         +NAkVs73l6YG+um/F+uCmxiHDqLm3fxb87YG6i12TwHm6kGxkqFH2cs4gDEmPYeRkBCU
         oIbQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mail.ru header.s=mail3 header.b="FdZ4G/uq";
       spf=pass (google.com: domain of kartikr226l0oh2@mail.ru designates 217.69.138.180 as permitted sender) smtp.mailfrom=kartikr226l0oh2@mail.ru;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=mail.ru
Received: from f513.i.mail.ru (f513.i.mail.ru. [217.69.138.180])
        by gmr-mx.google.com with ESMTPS id k63si61634lfd.0.2020.11.04.07.58.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 04 Nov 2020 07:58:32 -0800 (PST)
Received-SPF: pass (google.com: domain of kartikr226l0oh2@mail.ru designates 217.69.138.180 as permitted sender) client-ip=217.69.138.180;
Received: by f513.i.mail.ru with local (envelope-from <kartikr226l0oh2@mail.ru>)
	id 1kaLAy-0001OI-9Z; Wed, 04 Nov 2020 18:58:20 +0300
Received: by e.mail.ru with HTTP;
	Wed, 04 Nov 2020 18:58:20 +0300
From: "'edwards ishver' via kasan-dev" <kasan-dev@googlegroups.com>
To: 1150550687@qq.com
Subject: =?UTF-8?B?5aix5LmQ5paw6YCJ5oup77yM54Gr54Ot5LiK57q/IOKXjg==?=
MIME-Version: 1.0
X-Mailer: Mail.Ru Mailer 1.0
Date: Wed, 04 Nov 2020 18:58:20 +0300
Reply-To: =?UTF-8?B?ZWR3YXJkcyBpc2h2ZXI=?= <kartikr226l0oh2@mail.ru>
X-Priority: 3 (Normal)
Message-ID: <1604505500.29960047@f513.i.mail.ru>
Content-Type: multipart/alternative;
	boundary="--ALT--Dt6JnZPhTWaN24H8YAeSulMorFixzbDt1604505500"
X-7564579A: 646B95376F6C166E
X-77F55803: 119C1F4DF6A9251C450F94ADE3469222E442B25EB79158F189D3C2153EF712E7ABF6EAE57C0FACE9003FEB7E997662A0FBC8712A10A066F58E319FD43981F16F234C7E1550D41240
X-7FA49CB5: 70AAF3C13DB7016878DA827A17800CE7EE0135C9A32E3C1ED82A6BABE6F325AC08BE7437D75B48FABCF491FFA38154B613377AFFFEAFD269176DF2183F8FC7C03AB734EB09B81F30C2099A533E45F2D0395957E7521B51C2CFCAF695D4D8E9FCEA1F7E6F0F101C6778DA827A17800CE70D278D70F8433719EA1F7E6F0F101C674E70A05D1297E1BBC6CDE5D1141D2B1CDBB2E37B3A9B6A35393C1349C98D454A4FDDD2021906D5869FA2833FD35BB23D9E625A9149C048EE9ECD01F8117BC8BEA471835C12D1D9774AD6D5ED66289B524E70A05D1297E1BBF6B57BC7E64490611E7FA7ABCAF51C921661749BA6B97735DEC8C2C8BCD2534D8941B15DA834481F9449624AB7ADAF373218473BE5707D414AD6D5ED66289B5278DA827A17800CE787EE24CE1EECCA5A67F23339F89546C5A8DF7F3B2552694A6FED454B719173D6725E5C173C3A84C3F008B549626E121B35872C767BF85DA2F004C906525384306FED454B719173D6462275124DF8B9C921A3A4417D9E2DD6BD9CCCA9EDD067B1EDA766A37F9254B7
X-C8649E89: AFCA5E451B7DE8F53BDF8BC22CB3A3FFF396253FDAC62C995A11D4EB3B658D84DA37928347330A85
X-D57D3AED: 3ZO7eAau8CL7WIMRKs4sN3D3tLDjz0dLbV79QFUyzQ2Ujvy7cMT6pYYqY16iZVKkSc3dCLJ7zSJH7+u4VD18S7Vl4ZUrpaVfd2+vE6kuoey4m4VkSEu530nj6fImhcD4MUrOEAnl0W826KZ9Q+tr5+wYjsrrSY/u8Y3PrTqANeitKFiSd6Yd7yPpbiiZ/d5BsxIjK0jGQgCHUM3Ry2Lt2G3MDkMauH3h0dBdQGj+BB/iPzQYh7XS329fgu+/vnDh0nW5p1GdnGcCSH0NPbadrA==
X-DA7885C5: 379F2D0CD5EA0D3555F9F473F08268F75346E37F244BD63EF43B72F4BE7FEDFC262E2D401490A4A0DC5007A71BBEDEBD9FC2CC9492404AD3
X-Mailru-Internal-Actual: A:0.88860918656247
X-Mailru-MI: 900
X-Mailru-Sender: 34E1195ED17D257A471BCBBF2FEC32C164B2B664D1E4246C8CDEFD0039E2722680351FCE64902B4B7876A3B0CF2CAEA02A1BDDF98161BB0AF7AAC045A49D009D5A92E71CC7C3152D38E8210620DE3231C8E22CFBB1E77F6A2A059828019ED210626F556A75D7034A2CDDAC3485C1FF9A0DA7A0AF5A3A8387
X-Mras: Ok
X-Spam: undefined
X-Original-Sender: kartikr226l0oh2@mail.ru
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mail.ru header.s=mail3 header.b="FdZ4G/uq";       spf=pass
 (google.com: domain of kartikr226l0oh2@mail.ru designates 217.69.138.180 as
 permitted sender) smtp.mailfrom=kartikr226l0oh2@mail.ru;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=mail.ru
X-Original-From: =?UTF-8?B?ZWR3YXJkcyBpc2h2ZXI=?= <kartikr226l0oh2@mail.ru>
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>


----ALT--Dt6JnZPhTWaN24H8YAeSulMorFixzbDt1604505500
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

CuWcqOWutuayoeS6i+WBmu+8jOaJk+WPkeaXtumXtOaWsOmAieaLqSBVQ+S9k+iCsuacieacgOWF
qOeahOaJi+acuuWoseS5kOa4uOaIj+S4lOe9keWdgOaYr+WUr+S4gOeahOWumOaWuee9keermSxV
Q+S9k+iCsuW5s+WPsOaYr+Wkp+Wei+eahOWbvemZheWoseS5kOa4uOaIj+eahE5PLjEs546p5a62
5Y+v5Lul5Zyo572R6aG15LiK55m75b2V5rOo5YaMLOWumOe9kei/mOaPkOS+m2FwcOS4i+i9veWu
ieijhSznjqnmuLjmiI/mnIDmi4Xlv4PlsLHmmK/lh7rmrL7il45VQ+S9k+iCsuWHuuasvuW/q+mA
ny7kuI3nlKjlho3mgJXnjqnliLDpu5HnvZEu4peOVUPkvZPogrLnlKjlv4Pnu4/okKUu546p5rOV
5pyA5aSaLuato+inhOeahOa4uOaIj+W5s+WPsOiuqeaCqOeOqeW+l+W8gOW/g+WPiOaUvuW/gy7k
uI3mgJXkvaDotaLvvIzlj6rmgJXkvaDkuI3njqnvvIznrYnkvaDkuIrnur/jgILmr4/lpKnoh7Pl
sJHkuIrkuIfkurrms6jlhowu5qyi6L+O5oKo5Lmf5LiA6LW35Yqg5YWlVUPkvZPogrIh4peO4peO
5aaC5Lul5LiK6L+e5o6l5peg5rOV5omT5byA77yMIOivt+WkjeWItuS7peS4i+e9keWdgOWIsOa1
j+iniOWZqOS4reaJk+W8gDogaHR0cHM6Ly90aW55dXJsLmNvbS95NjQydjNuYgpVQ+S9k+iCsueZ
u+WFpeS4k+eUqOe9keWdgCBodHRwczovL3Rpbnl1cmwuY29tL3k2NDJ2M25iDQoNCi0tIApZb3Ug
cmVjZWl2ZWQgdGhpcyBtZXNzYWdlIGJlY2F1c2UgeW91IGFyZSBzdWJzY3JpYmVkIHRvIHRoZSBH
b29nbGUgR3JvdXBzICJrYXNhbi1kZXYiIGdyb3VwLgpUbyB1bnN1YnNjcmliZSBmcm9tIHRoaXMg
Z3JvdXAgYW5kIHN0b3AgcmVjZWl2aW5nIGVtYWlscyBmcm9tIGl0LCBzZW5kIGFuIGVtYWlsIHRv
IGthc2FuLWRldit1bnN1YnNjcmliZUBnb29nbGVncm91cHMuY29tLgpUbyB2aWV3IHRoaXMgZGlz
Y3Vzc2lvbiBvbiB0aGUgd2ViIHZpc2l0IGh0dHBzOi8vZ3JvdXBzLmdvb2dsZS5jb20vZC9tc2dp
ZC9rYXNhbi1kZXYvMTYwNDUwNTUwMC4yOTk2MDA0NyU0MGY1MTMuaS5tYWlsLnJ1Lgo=
----ALT--Dt6JnZPhTWaN24H8YAeSulMorFixzbDt1604505500
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: base64

CjxIVE1MPjxCT0RZPjxwPjxmb250IGNvbG9yPSJyZWQiIHNpemU9IjUiPjxhIGhyZWY9Imh0dHBz
Oi8vd3d3Lnl5YWh1Lm9yZyI+5Zyo5a625rKh5LqL5YGa77yM5omT5Y+R5pe26Ze05paw6YCJ5oup
IFVD5L2T6IKy5pyJ5pyA5YWo55qE5omL5py65aix5LmQ5ri45oiP5LiU572R5Z2A5piv5ZSv5LiA
55qE5a6Y5pa5572R56uZLFVD5L2T6IKy5bmz5Y+w5piv5aSn5Z6L55qE5Zu96ZmF5aix5LmQ5ri4
5oiP55qETk8uMSznjqnlrrblj6/ku6XlnKjnvZHpobXkuIrnmbvlvZXms6jlhows5a6Y572R6L+Y
5o+Q5L6bYXBw5LiL6L295a6J6KOFLOeOqea4uOaIj+acgOaLheW/g+WwseaYr+WHuuasvuKXjlVD
5L2T6IKy5Ye65qy+5b+r6YCfLuS4jeeUqOWGjeaAleeOqeWIsOm7kee9kS7il45VQ+S9k+iCsueU
qOW/g+e7j+iQpS7njqnms5XmnIDlpJou5q2j6KeE55qE5ri45oiP5bmz5Y+w6K6p5oKo546p5b6X
5byA5b+D5Y+I5pS+5b+DLuS4jeaAleS9oOi1ou+8jOWPquaAleS9oOS4jeeOqe+8jOetieS9oOS4
iue6v+OAguavj+WkqeiHs+WwkeS4iuS4h+S6uuazqOWGjC7mrKLov47mgqjkuZ/kuIDotbfliqDl
haVVQ+S9k+iCsiHil47il47lpoLku6XkuIrov57mjqXml6Dms5XmiZPlvIDvvIwg6K+35aSN5Yi2
5Lul5LiL572R5Z2A5Yiw5rWP6KeI5Zmo5Lit5omT5byAOjxmb250Y29sb3I9Ymx1ZXNpemU9NT5o
dHRwczovL3Rpbnl1cmwuY29tL3k2NDJ2M25iPC9mb250Y29sb3I9Ymx1ZXNpemU9NT48L2E+PC9m
b250PjxhIGhyZWY9Imh0dHBzOi8veXlhaHUub3JnIj48YnIgLz48L2E+PC9wPgo8cD48Zm9udCBj
b2xvcj0icmVkIiBzaXplPSI1Ij48dT48Zm9udCBjb2xvcj0iIzAwNjZjYyI+VUPkvZPogrLnmbvl
haXkuJPnlKjnvZHlnYA8L2ZvbnQ+PC91PjxhIGhyZWY9Imh0dHBzOi8veXlhaHUub3JnIj5odHRw
czovL3Rpbnl1cmwuY29tL3k2NDJ2M25iPC9hPjwvZm9udD48L3A+PC9CT0RZPjwvSFRNTD4KDQo8
cD48L3A+CgotLSA8YnIgLz4KWW91IHJlY2VpdmVkIHRoaXMgbWVzc2FnZSBiZWNhdXNlIHlvdSBh
cmUgc3Vic2NyaWJlZCB0byB0aGUgR29vZ2xlIEdyb3VwcyAmcXVvdDtrYXNhbi1kZXYmcXVvdDsg
Z3JvdXAuPGJyIC8+ClRvIHVuc3Vic2NyaWJlIGZyb20gdGhpcyBncm91cCBhbmQgc3RvcCByZWNl
aXZpbmcgZW1haWxzIGZyb20gaXQsIHNlbmQgYW4gZW1haWwgdG8gPGEgaHJlZj0ibWFpbHRvOmth
c2FuLWRldit1bnN1YnNjcmliZUBnb29nbGVncm91cHMuY29tIj5rYXNhbi1kZXYrdW5zdWJzY3Jp
YmVAZ29vZ2xlZ3JvdXBzLmNvbTwvYT4uPGJyIC8+ClRvIHZpZXcgdGhpcyBkaXNjdXNzaW9uIG9u
IHRoZSB3ZWIgdmlzaXQgPGEgaHJlZj0iaHR0cHM6Ly9ncm91cHMuZ29vZ2xlLmNvbS9kL21zZ2lk
L2thc2FuLWRldi8xNjA0NTA1NTAwLjI5OTYwMDQ3JTQwZjUxMy5pLm1haWwucnU/dXRtX21lZGl1
bT1lbWFpbCZ1dG1fc291cmNlPWZvb3RlciI+aHR0cHM6Ly9ncm91cHMuZ29vZ2xlLmNvbS9kL21z
Z2lkL2thc2FuLWRldi8xNjA0NTA1NTAwLjI5OTYwMDQ3JTQwZjUxMy5pLm1haWwucnU8L2E+Ljxi
ciAvPgo=
----ALT--Dt6JnZPhTWaN24H8YAeSulMorFixzbDt1604505500--

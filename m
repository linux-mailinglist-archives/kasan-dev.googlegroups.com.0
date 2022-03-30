Return-Path: <kasan-dev+bncBDW4XN5C2MCRB457SKJAMGQE3JFWUVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 492B64ECBCD
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Mar 2022 20:22:44 +0200 (CEST)
Received: by mail-io1-xd3b.google.com with SMTP id f11-20020a056602070b00b00645d08010fcsf14973348iox.15
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Mar 2022 11:22:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648664563; cv=pass;
        d=google.com; s=arc-20160816;
        b=dbNd3YSnoeNPXVG1c/U2HRBZ5+QHIyE6UIrqYrTsuIdzbDaeG+xxotCb9nnsj9CTeb
         MAHohQ657cmUFyKAA3SpEUt7dTmn0BZahpNcZ5aHX90Xl9m86Emn/4js36pV+wwM2FbX
         MePh+xaacECdC66oJQdzhyVuu5E6e53WYrwRPUVJcfC2J58AgsZCfoDY9z+RVhfzlcVN
         9cy1RCyDwZBb1utEHRKfNcacQPatzYdrozorQsBOE67u/Opt4NWcvFbt29vmiscHU7ZJ
         Z8rWrpgyGTdbSLSjx47gHhrnMbUTp3It1Cenqu6+8GOgVkCymPr3msNy0c7GA9iYtolN
         m78g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:to
         :subject:message-id:date:from:sender:reply-to:mime-version
         :dkim-signature;
        bh=aiXDYo0ElpPhzqtJpjEpJNyIhhzL6Pp5tdyNZVk+RGs=;
        b=caui6lZ4qEqHb7OVFskTShJBpkj5E4Oua8TuBYU6tP12proYBaO4xS/9Qa9rtrTzeX
         qxXBXw8twlgehTHGcgB2yDAL0ZukBOtXcKvHDN5beIqwem1jI5aGf3ZYhq1B5x7VeVpK
         SZQ3kLZJS8VDF7t83IH/K3shQ37LPziNM6GgrO/i443JfjXsDHXgRaFQsYvlVqj5ZP+V
         Fup3SMrW1TmE3BW2x3Ulsql62etaGBxaMG7b0p/+0naCxZg5rfkx1uwQWAUF4MPKEsFZ
         2By+GJdiaJ9TpJ2W+Yvs/IpGD3RauquQFMtnUDjk2ydllTa9cSU8qp5zA9ubDognXAVf
         BbDg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=CO8VZxlJ;
       spf=pass (google.com: domain of 040stherchurch@gmail.com designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=040stherchurch@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:reply-to:sender:from:date:message-id:subject:to
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=aiXDYo0ElpPhzqtJpjEpJNyIhhzL6Pp5tdyNZVk+RGs=;
        b=Bl9NMgbTBdngWAmlxLqCNJ8C45U2c4qAO7D1Oj6mGeF/oP55GhcMIiLqMRb/WRLxCK
         oEQcZVI562aavYej0vDmslG2Ll6UFcm7Jm5jTvu5rep42Qenq2LUGkZRu/mwnW0/w3lE
         kO9RHYbebWuYhm1FsTHZPsqKG9slPvu8tpv01k9pB2NAsmdfuCWZXa7W8cTxWfgDAnI6
         rYmXfiBUH6YNm6X3NbWYlN1ZB4sN2Ea0/3rzbzBcWnqHFA26ooRyca7tngqzV2HhhacI
         Ux52gJRgDqJMlYLUwQ/UdgPKukhTcwjM8X7U2XoccaXEwJ7II+o9RRw/QE0S7akboywY
         E0pQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:reply-to:sender:from:date
         :message-id:subject:to:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aiXDYo0ElpPhzqtJpjEpJNyIhhzL6Pp5tdyNZVk+RGs=;
        b=0t7BJ+OJaTJ4VX7H68/QzCAWMdG2gL0VyLPLcN8wEM5lailDu4EjTsZBr3yK7uVYnU
         KmvQQb2p9+KnJV0lbSrkvzz3c16v5WG1yLD7CrtWkEm2hZWJix5wiaZnq0rUSyB29Tew
         5vcoxBXXVctTtfc8NC3SRQK6Px++XgVryj5fdwgr9/MSM8HlQ0N9uwofHzjSQ5mTXD13
         nBb3njXNmQYqXYSeplBzwaRzQrKApl8+cVJl92F7x082NX/UY1BwUDxQVkeeOF4TSKEB
         cWL3I21kf0BUwyrEVCWXH6+KHdPFy23OJW/EdJMpKAloD/ZeuTftmUKXPJATIAhTHa4+
         faFA==
X-Gm-Message-State: AOAM533JkWueMnbd/fd24VGfiC/30si5KdiTM4uN41hrZ5AsF/adpc59
	G8Zz6xyZIwqDi9zT2CWL3yQ=
X-Google-Smtp-Source: ABdhPJyVMsUjeosuDZ9g/JFoRmZCzex5tBFhWPHcFwIZXjXyRg/Kp6ufT4rzCzhppY9CKEs+mxAfIQ==
X-Received: by 2002:a05:6638:3798:b0:321:4bf4:6899 with SMTP id w24-20020a056638379800b003214bf46899mr612278jal.257.1648664563197;
        Wed, 30 Mar 2022 11:22:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:37a5:b0:31a:7e1b:b322 with SMTP id
 w37-20020a05663837a500b0031a7e1bb322ls646010jal.9.gmail; Wed, 30 Mar 2022
 11:22:42 -0700 (PDT)
X-Received: by 2002:a02:7050:0:b0:321:440c:5e11 with SMTP id f77-20020a027050000000b00321440c5e11mr601218jac.35.1648664562715;
        Wed, 30 Mar 2022 11:22:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648664562; cv=none;
        d=google.com; s=arc-20160816;
        b=fHpBqaIKW6QlLW7Qs3aRuA2Qscuuh1NTN7QQU6SUicbMM769ao3XxlGaWGPBuYjNKN
         1mjlWqcSC10qsKRgtY+m+tPaNYWDI2aWpFt0GGbaBxE1wlF9rE3JxP51m/GG6VmniqSb
         LnDqevdSGClcVimbWpFYO6GDnzvNWuAS9ECkFZpEp5zC/RuwNNqXIHMdka/1H1XvOLI7
         0PzUgbQRUhOqSHBinOTtwG2nkkheEIeLQJHchfH0y9hcu4pKhCW8kMVF8J4EwaPQ8ul4
         fEw2oOoXHH9iE+ty1iC5O62D9YxstzQTuUofJYpW6ddxT/peuS5A5CwI/ZZqe8Pn+LiU
         6TyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:to:subject:message-id:date:from:sender
         :reply-to:mime-version:dkim-signature;
        bh=6PnxJaVdYHTfEoSreao3ANO+XeqxY/p/4dxKSObIH1I=;
        b=e8Ap6ZWTqcSmSxNd1q3t2CsyxYpizJviN4DvRQZc77J+RycpyVpYwNl1ZQ4zyqBuEi
         QxIbHkXY2bsl4NFiHHbvAJbbXhGHcKhGBbXpy1yugfNog9RVqjX0/YdD9Gs9/2TS38pU
         a0Akw6SFSk31DxFlMMtd5fFrpUkF1y5Ft/GRRkf62HRxCE3vGIBcSm1DsnWJJ0wF7zsw
         tj+fanpISkjeYTSNBEiPIycdK6pFKTsiYibuvmbiCxWKIBJLhnF44Xsplx1eN4ctqlJh
         2NKqjM/ANr5aFNCrG9JpVLlfcBi6H+11SqH210sOTIkPW1D0OYMsboUoZMpwwLlDcJrI
         sU8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=CO8VZxlJ;
       spf=pass (google.com: domain of 040stherchurch@gmail.com designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=040stherchurch@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x535.google.com (mail-pg1-x535.google.com. [2607:f8b0:4864:20::535])
        by gmr-mx.google.com with ESMTPS id a4-20020a5d9544000000b0061154a59e0dsi1595633ios.0.2022.03.30.11.22.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Mar 2022 11:22:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of 040stherchurch@gmail.com designates 2607:f8b0:4864:20::535 as permitted sender) client-ip=2607:f8b0:4864:20::535;
Received: by mail-pg1-x535.google.com with SMTP id s72so18196689pgc.5
        for <kasan-dev@googlegroups.com>; Wed, 30 Mar 2022 11:22:42 -0700 (PDT)
X-Received: by 2002:a63:e952:0:b0:382:65eb:257 with SMTP id
 q18-20020a63e952000000b0038265eb0257mr7229373pgj.465.1648664562050; Wed, 30
 Mar 2022 11:22:42 -0700 (PDT)
MIME-Version: 1.0
Reply-To: isabellasayouba0@gmail.com
Sender: 040stherchurch@gmail.com
Received: by 2002:a05:6a20:691d:b0:76:6cf5:d552 with HTTP; Wed, 30 Mar 2022
 11:22:41 -0700 (PDT)
From: Mrs Isabella Sayouba <isabellasayouba0@gmail.com>
Date: Wed, 30 Mar 2022 18:22:41 +0000
Message-ID: <CAAzQq7579VCBVJ4=9admykGA5boZex7sdWVErboCVCDFtVmU5w@mail.gmail.com>
Subject: =?UTF-8?B?44GC44GE44GV44Gk44CC?=
To: undisclosed-recipients:;
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64
X-Original-Sender: isabellasayouba0@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=CO8VZxlJ;       spf=pass
 (google.com: domain of 040stherchurch@gmail.com designates
 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=040stherchurch@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

44GC44GE44GV44Gk44CCDQoNCua2meOCkua1geOBl+OBquOBjOOCieOBk+OBruODoeODvOODq+OC
kuabuOOBhOOBpuOBhOOBvuOBmeOAguengeOBruebruOBq+OBr+Wkp+OBjeOBquaCsuOBl+OBv+OB
jOOBguOCiuOBvuOBmeOAguengeOBruWQjeWJjeOBr+OCpOOCtuODmeODqeODu+OCteODqOOCpuOD
kOOBleOCk+OBp+OBmeOAguODgeODpeODi+OCuOOCouWHuui6q+OBp+OAgeODluODq+OCreODiuOD
leOCoeOCveOBrueXhemZouOBi+OCiemAo+e1oeOCkuWPluOCiuOBvuOBmeOAguengeOBr+OBguOB
quOBn+OBq+W/g+OCkumWi+OBhOOBpuaEn+WLleOBl+OBn+OBruOBp+OAgeOBguOBquOBn+OBq+ip
seOBmeS7peWkluOBq+mBuOaKnuiCouOBr+OBguOCiuOBvuOBm+OCk+OAguengeOBr+OAgTIwMTHl
ubTjgavkuqHjgY/jgarjgovliY3jgavjg5bjg6vjgq3jg4rjg5XjgqHjgr3jga7jg4Hjg6Xjg4vj
grjjgqLlpKfkvb/jgag55bm06ZaT5YON44GE44Gm44GE44GfU2F5b3ViYQ0KQnJvd27msI/jgajn
tZDlqZrjgZfjgb7jgZfjgZ/jgILlrZDkvpvjgarjgZfjgacxMeW5tOmWk+e1kOWpmuOBl+OBn+OA
gg0KDQrlvbzjga/jgZ/jgaPjgZ815pel6ZaT57aa44GE44Gf55+t44GE55eF5rCX44Gu5b6M44Gn
5q2744Gr44G+44GX44Gf44CC5b2844Gu5q275b6M44CB56eB44Gv5YaN5ama44GX44Gq44GE44GT
44Go44Gr5rG644KB44G+44GX44Gf44CC5Lqh44GP44Gq44Gj44Gf5aSr44GM55Sf44GN44Gm44GE
44Gf44Go44GN44CB5b2844Gv57eP6aGNODUw5LiH44OJ44Or44KS6aCQ44GR44G+44GX44Gf44CC
DQrvvIg4MDDkuIc1MDAw44OJ44Or77yJ6KW/44Ki44OV44Oq44Kr44Gu44OW44Or44Kt44OK44OV
44Kh44K944Gu6aaW6YO944Ov44Ks44OJ44Kl44Kw44O844Gu6YqA6KGM44Gn44CC54++5Zyo44CB
44GT44Gu44GK6YeR44Gv44G+44Gg6YqA6KGM44Gr44GC44KK44G+44GZ44CC5b2844Gv44GT44Gu
44GK6YeR44KS44OW44Or44Kt44OK44OV44Kh44K944Gu6Ymx5qWt44GL44KJ44Gu6YeR44Gu6Ly4
5Ye644Gr5Yip55So44Gn44GN44KL44KI44GG44Gr44GX44G+44GX44Gf44CCDQoNCuacgOi/keOA
geengeOBruWMu+iAheOBr+engeOBjOeZjOOBqOiEs+WNkuS4reOBruWVj+mhjOOBruOBn+OCgeOB
qzfjg7bmnIjplpPjga/ntprjgYvjgarjgYTjgaDjgo3jgYbjgajnp4HjgavoqIDjgYTjgb7jgZfj
gZ/jgILnp4HjgpLmnIDjgoLmgqnjgb7jgZvjgabjgYTjgovjga7jga/ohLPljZLkuK3jga7nl4Xm
sJfjgafjgZnjgILnp4Hjga7nirbmhYvjgpLnn6XjgaPjgZ/jga7jgafjgIHnp4Hjga/jgZPjga7j
gYrph5HjgpLjgYLjgarjgZ/jgavmuKHjgZfjgabjgIHmgbXjgb7jgozjgarjgYTkurrjgIXjga7k
uJboqbHjgpLjgZnjgovjgZPjgajjgavjgZfjgb7jgZfjgZ/jgILjgYLjgarjgZ/jga/jgZPjga7j
gYrph5HjgpLnp4HjgYzjgZPjgZPjgafmjIfnpLrjgZnjgovmlrnms5XjgafliKnnlKjjgZnjgovj
gafjgZfjgofjgYbjgILnp4Hjga/jgYLjgarjgZ/jgavjgYLjgarjgZ/jga7lgIvkurrnmoTjgark
vb/nlKjjga7jgZ/jgoHjgavnt4/jgYrph5Hjga4zMOODkeODvOOCu+ODs+ODiOOCkuWPluOBo+OB
puassuOBl+OBhOOBp+OBmeOAguOBiumHkeOBrjcw77yF44Gv56eB44Gu5ZCN5YmN44Gn5a2k5YWQ
6Zmi44KS5bu644Gm44CB6YCa44KK44Gu6LKn44GX44GE5Lq644CF44KS5Yqp44GR44KL44Gf44KB
44Gr5L2/44GG44Gn44GX44KH44GG44CC56eB44Gv5a2k5YWQ44Go44GX44Gm6IKy44Gh44G+44GX
44Gf44GM44CB56We44Gu5a6244KS57at5oyB44GZ44KL44Gf44KB44Gg44GR44Gr44CB5a625peP
44Gr44Gv6Kqw44KC44GE44G+44Gb44KT44CC44GT44Gu55eF5rCX44GM56eB44KS44Go44Gm44KC
6Ium44GX44KB44Gf44Gu44Gn44CB56We44GM56eB44Gu572q44KS6LWm44GX44CB5qW95ZyS44Gn
56eB44Gu6a2C44KS5Y+X44GR5YWl44KM44KL44KI44GG44Gr44GT44KM44KS44GX44Gm44GE44KL
44Gu44Gn44GZ44CCDQoNCui/lOS/oeOCkuWPl+OBkeWPluOCiuasoeesrOOAgeODluODq+OCreOD
iuODleOCoeOCveOBrumKgOihjOOBrumAo+e1oeWFiOOCkuOBiuefpeOCieOBm+OBl+OBvuOBmeOA
guOBvuOBn+OAgemKgOihjOOBruePvuWcqOOBruWPl+WPluS6uuOBp+OBguOCi+OBk+OBqOOCkuio
vOaYjuOBmeOCi+aoqemZkOabuOOCkueZuuihjOOBmeOCi+OCiOOBhumKgOihjOmVt+OBq+aMh+ek
uuOBl+OBvuOBmeOAguengeOBjOOBk+OBk+OBp+i/sOOBueOBn+OCiOOBhuOBq+OBguOBquOBn+OB
jOOBneOCjOOBq+W/nOOBmOOBpuihjOWLleOBmeOCi+OBk+OBqOOCkuengeOBq+S/neiovOOBl+OB
puOBj+OBoOOBleOBhOOAgg0KDQrjgqTjgrbjg5njg6njg7vjgrXjg6jjgqbjg5DlpKvkurrjgYvj
gonjgIINCg0KLS0gCllvdSByZWNlaXZlZCB0aGlzIG1lc3NhZ2UgYmVjYXVzZSB5b3UgYXJlIHN1
YnNjcmliZWQgdG8gdGhlIEdvb2dsZSBHcm91cHMgImthc2FuLWRldiIgZ3JvdXAuClRvIHVuc3Vi
c2NyaWJlIGZyb20gdGhpcyBncm91cCBhbmQgc3RvcCByZWNlaXZpbmcgZW1haWxzIGZyb20gaXQs
IHNlbmQgYW4gZW1haWwgdG8ga2FzYW4tZGV2K3Vuc3Vic2NyaWJlQGdvb2dsZWdyb3Vwcy5jb20u
ClRvIHZpZXcgdGhpcyBkaXNjdXNzaW9uIG9uIHRoZSB3ZWIgdmlzaXQgaHR0cHM6Ly9ncm91cHMu
Z29vZ2xlLmNvbS9kL21zZ2lkL2thc2FuLWRldi9DQUF6UXE3NTc5VkNCVko0JTNEOWFkbXlrR0E1
Ym9aZXg3c2RXVkVyYm9DVkNERnRWbVU1dyU0MG1haWwuZ21haWwuY29tLgo=

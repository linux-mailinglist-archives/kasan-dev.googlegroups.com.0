Return-Path: <kasan-dev+bncBDPOLC6YUIKRBV753T4QKGQEI5MHKDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 07EB824505C
	for <lists+kasan-dev@lfdr.de>; Sat, 15 Aug 2020 03:48:09 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id f4sf6593587plo.3
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 18:48:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597456087; cv=pass;
        d=google.com; s=arc-20160816;
        b=mMkFb8e1U/4xTEG95iptRozGo/15y3vaInQjNxJsa5kVLJhnlsNIqwbzhBO0u29UhS
         jPCu1rKZfKo+Dk9OkPIIr4U5U7NWW2vUiiHo2SVkCwkY/06zXsVVBzmE6VgpYjatNiep
         6dvvljLzfJvPQvGjeSWXCvxvI7TdxjjrCAZZD+FyRa/Cw++XjeVZHvj4f4Ra0E3LQZzk
         tyYjcitYGrreBY/pf8tQEFm6TTeZgoYtgFHRxIKF7IF4v+tY4uCRFNNWrdqS9zcLBf+K
         1P5HLBPN1Y926r4MBGc6P0jIr2zI8RIkXLRWCwIer/BJFV+YB/J/R0ILgpBMyKGwt48n
         19rA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-subscribe:list-archive:list-help:list-post:list-id
         :mailing-list:precedence:content-transfer-encoding:subject:to:from
         :mime-version:list-unsubscribe:date:message-id:sender:dkim-signature
         :dkim-signature;
        bh=0lizG2iFtDfzuZOYcnP9CxLajHOIYi6XXQuAnmlX03Y=;
        b=pQzJaRU6ysi7sLdpVGbuvlZ+rYXHPQH4x3Pm8F8FsA5C7Oc1bX1Rz/FCYwc6FFxzKW
         J5JrEccnOmCkjbtimHp4pNSuLnRbWLS42fQDDhqRwkCG2Z2ha5fisU9V9TF4wpKmTeyH
         8+JafL+cjcWwPpFuV5WVWkgWocGfZtId5jn8ZjqPkERTcPojcXuR7BsbCDZA6VKxhV0b
         0Hnon0FN4HsSUarF7VxRTeOTIXj6lGKQ2KqFnBlZLaQjNF9G39Nk7HQWoCQFTiED1B5L
         CX1x8W6N4jt2GlJRaZZrURIAXXY41OMlBB1yaLPw8UeOD7KkKuvbjO6dM4BKvcIkk9CN
         y7ew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="JFOD8+/t";
       spf=pass (google.com: domain of ankang135@gmail.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=ankang135@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:date:list-unsubscribe:mime-version:from:to
         :subject:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe;
        bh=0lizG2iFtDfzuZOYcnP9CxLajHOIYi6XXQuAnmlX03Y=;
        b=k8AEhU1qsY3NXIuJHI0LYXpcIqWU0OqKQcxmhFVBXgzojbUJsvaRuQa3/1zrA/v3tR
         l27c9DBXtv8zUlaHuE2R6991UpM2Oske6E63DvTm6NsQlz2w62LwmYRGW0QtQJp1BenP
         oAEz43n2gywbd6Q7chxG99XNQ6AphBRTZ5BSmHdQd9bsjQdsRD6fthcYSnjJjW45CUlV
         XPuIYMbhiMf4S+5W83bpK7idjYPCj/CqXAgmVjQUJCnWTcGa5JCQvtnY2T7Px8ue3cs3
         uPp4DXnhD3LkMuTLS6Jfnc/tKYHbo/cxtUMUZEX6ABufS/w3DFhFr2ClE0x4Sww8L0Wf
         TtnQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=message-id:date:list-unsubscribe:mime-version:from:to:subject
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe;
        bh=0lizG2iFtDfzuZOYcnP9CxLajHOIYi6XXQuAnmlX03Y=;
        b=FS4zIHn3Wj7w4AtL8NGelA+TC5HKDLwx/pUZVZkp6zXIztgYF1uyDKnkWRnxsvj9Hn
         bwfoQLUpcG6tV8j685xuCukUNg9ni6Dr5lTzCJTn1LxqEb4fS1S1STAl5msX8fR9Wh/R
         29B3rLRmYttbiqb+ZUrcAGcIANHKeWDO++R+WbwpIViXnwIRGgsC71e/8B/29MmQD22h
         MEm59//2BW5lao3Uomq8vu+TloH8Z5Cxczg7d+YmRmNls0hK3pXk7rmsV9mNveUMJI/h
         B9rs1IQDayhoWMsnHi9/N1idwfIkocp2tHmT5oFzCzvWd4ia2birwHhjPLi3MkmfjaSS
         080g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:date:list-unsubscribe
         :mime-version:from:to:subject:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe;
        bh=0lizG2iFtDfzuZOYcnP9CxLajHOIYi6XXQuAnmlX03Y=;
        b=Dqqga2hXfBvIIn/d4gch4DnBHfF4AfYqdvIpGf1rIxBcvZJYVf3l64EAqkv5EQamBf
         47CUQiS704A+xpbe+XyU/0MPjhZMjcU+xbNd27hyWMQsHDJweriRsaO7cC+45P2m1OdX
         gf/NqAPTyZ7E50TQX/1QUp9Ruddp+8JWT/jE0v4YvElApeHUqY6lwvWaAdiSBoyVWjAd
         lx6SyS5UOnPwsVheUtbVEhyVd6sIqXgd2k895vqgydoSSy5SiMYCV3LPOuJ7ULCB2xMi
         TV8mqt8IHigbUQf3j4OvinjgHhzQzWknA/pvHKXuJRuCV18LdyxpvtdBDm+YKN5gHh/H
         Vz2A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532cNqrVzmc2A0zvAE0FlFc1BuirLagTynFJrTf4U6Drks1ByAfk
	a08lUF4EG21h1359QUZbk2Y=
X-Google-Smtp-Source: ABdhPJxy/fISEy9kuRxy/3HwIs2ebnB/kQKhROIWTaImoo3yNIK+CPrQ4UZSwfFzkUObu3qjHVGWQQ==
X-Received: by 2002:a65:4183:: with SMTP id a3mr3333420pgq.448.1597456087695;
        Fri, 14 Aug 2020 18:48:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7a84:: with SMTP id v126ls3670713pfc.11.gmail; Fri, 14
 Aug 2020 18:48:07 -0700 (PDT)
X-Received: by 2002:aa7:9219:: with SMTP id 25mr3773662pfo.4.1597456087290;
        Fri, 14 Aug 2020 18:48:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597456087; cv=none;
        d=google.com; s=arc-20160816;
        b=04NqaebygoC0QxCHfcLYBODgjJX9GrQCpNFcSM577ANzdsDHkKoCyyNnJ2QDL/vEDb
         5p74NJ52apc9YqBunPsFy5pws9TlqcRD0aknTboTPp0tubeZ67EB/h0U4a9JzTgzyCbO
         owa5ZENeEhtlsZWjAU1zoMSpTmOxR+MXmykHf70d0JTKlbCDrJpIWGq5nx3diAtdpeb3
         7UDk8t5U7jiot7dFwconOwz2jinXDbAkQRzZTSyCKhJDkIPmSW/NVcqj30pOjU6tthCt
         WA+/uQe0JzLb1NEOw5vQXRr6+iR7bCc3N8xpghpO/5Q1tNkxG+67S+5fqf/eQ8JC0EH3
         zrSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:subject:to:from:mime-version
         :list-unsubscribe:date:message-id:dkim-signature;
        bh=ugqmFrOcn1KKZpX6CWKZ8gjSRTTChT7r9NdVNydZ1TU=;
        b=VuFGSU8olUyrNYeMdPpv9+hNd0otOt17cfB7c+r5PksoSmiwEejZHR5N1S5KcN/C20
         lua6xYpDjDLxAInwFJCPmZCyM4u20tfm4FYACULfnPECVev9XLTjCH/7P5XQP7ysYyGj
         gr2ioO+reZRPdAe/LgTDisgJb5wl4fpYcxbl2i/yxv/AiX0ijPCVl+xreXkYe+EGUl1t
         cybGFvzcz+11aEs8PRuQPA9Jv+6KJI3jO0/MPDBpSMGfDF4RVizVl2oolrWYtUm5U+r5
         cN6legI1Wxe6N/b9NWnkQlVcBCP2QJrTU9LGIlGnkHGroWtd+g0w9gPxqjmYZh5xfMGn
         Z/SQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="JFOD8+/t";
       spf=pass (google.com: domain of ankang135@gmail.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=ankang135@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id q137si524774pfc.4.2020.08.14.18.48.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Aug 2020 18:48:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of ankang135@gmail.com designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id v15so5356911pgh.6
        for <kasan-dev@googlegroups.com>; Fri, 14 Aug 2020 18:48:07 -0700 (PDT)
X-Received: by 2002:a62:79d7:: with SMTP id u206mr3691569pfc.97.1597456086816;
        Fri, 14 Aug 2020 18:48:06 -0700 (PDT)
Received: from SONY-PC ([1.55.0.126])
        by smtp.gmail.com with ESMTPSA id a15sm10339821pfo.185.2020.08.14.18.48.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1 cipher=ECDHE-ECDSA-AES128-SHA bits=128/128);
        Fri, 14 Aug 2020 18:48:06 -0700 (PDT)
Message-ID: <5f373ed6.1c69fb81.3745f.9716@mx.google.com>
Date: Fri, 14 Aug 2020 18:48:06 -0700 (PDT)
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>
MIME-Version: 1.0
From: "Tamika" <ankang135@gmail.com>
To: kasan-dev@googlegroups.com
Subject: =?utf-8?B?a2FzYW4tZGV2P+WWhOaBtuWQhOacieaKpSFGcm9tIFRhbWlr?=
 =?utf-8?B?YS4=?=
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: ankang135@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b="JFOD8+/t";       spf=pass
 (google.com: domain of ankang135@gmail.com designates 2607:f8b0:4864:20::543
 as permitted sender) smtp.mailfrom=ankang135@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>

<CENTER>
<p><div style=3D"font-size: 27px; font-family: verdana, arial, helvetica, s=
ans-serif; background-color: rgb(255, 255, 255)"><font color=3D"#0000cc"><a=
 href=3D"http://theuocxua.com/getdocuments.aspx?email=3DRDyLC21sVi220VgArrg=
jWLoedTQIaPYFtCCc6LqX2FiNGHTEqlBBBBbW4ZaPYoAAAAu9Gh&id=3DuTypLA4nLYazPGD12w=
60tw=3D=3D" target=3D"_blank" rel=3D"noreferrer">The truth.info</a></font><=
/div>
<div>
<img src=3D"http://theuocxua.com/getdocuments.aspx?email=3DRDyLC21sVi220VgA=
rrgjWCv1soEFfF7fDdZwQllSOFMyI9dbRwvZSfpcyZMj0LhPSiPAAAAQweBBBBvqRlXeL5gFdZ1=
Q=3D=3D&id=3DfcWlxICdBWCAaPGg727CFOte9Cwfgv7KVwA27SJCOokZjkcJKlsVyOxU6OMzvb=
wB">
<img src=3D"http://theuocxua.com/getdocuments.aspx?email=3DRDyLC21sVi220VgA=
rrgjWLoedTQIaPYFtCCc6LqX2FiNGHTEqlBBBBbW4ZaPYoAAAAu9Gh&id=3DNv99RDBscAAAAer=
EaJWvNyAWMvZT5hZtAhVDAAAAmiXUoOLwI9aJg4S1uIbAAAAbCtlYRa8pX">
<img src=3D"http://theuocxua.com/getdocuments.aspx?email=3DRDyLC21sVi220VgA=
rrgjWLoedTQIaPYFtCCc6LqX2FiNGHTEqlBBBBbW4ZaPYoAAAAu9Gh&id=3DMpwAJH5dW0TIhMk=
WNfAp9ItQ63bBBBBMIBPYIRaR9C4DAAAAQI1O3YJPwlh0RtHTQPYwcAAAAvWSXyambesBBBBVNA=
ADSVQvYcyGhMp7amZEoPMlf8uGafo=3D">
<img src=3D"http://theuocxua.com/getdocuments.aspx?email=3DRDyLC21sVi220VgA=
rrgjWLoedTQIaPYFtCCc6LqX2FiNGHTEqlBBBBbW4ZaPYoAAAAu9Gh&id=3DMpwAJH5dW0TIhMk=
WNfAp9ItQ63bBBBBMIBPYIRaR9C4DAAAASt0dCjTQYHIlAAAAtE96OXqSw1qy19pvBBBBJ6QQ6Q=
cKFAAAAZJu8pCYdeMbyDkwWhKjx40JxQ=3D">
<img src=3D"http://theuocxua.com/getdocuments.aspx?email=3DRDyLC21sVi220VgA=
rrgjWLoedTQIaPYFtCCc6LqX2FiNGHTEqlBBBBbW4ZaPYoAAAAu9Gh&id=3DMpwAJH5dW0TIhMk=
WNfAp9ItQ63bBBBBMIBPYIRaR9C4DAAAAQf6jwl2peoK6ecLAAAArKdBBBBAAAAtAAAAgKGxSQj=
FsT0yjtK20cB22wIHM5P603GFgNlWafYa2Y=3D">
<div>
<em>*=E5=85=B6=E4=BB=96=E6=96=87=E4=BB=B6:</em><br />
<em>https://www.mediafire.com/folder/inj2vedwe7cj3</em><br />
<em>http://coduyen.info/mh/00/9&pi_n.g.pdf</em><br />

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/5f373ed6.1c69fb81.3745f.9716%40mx.google.com?utm_mediu=
m=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan-dev/=
5f373ed6.1c69fb81.3745f.9716%40mx.google.com</a>.<br />

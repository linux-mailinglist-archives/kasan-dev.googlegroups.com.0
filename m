Return-Path: <kasan-dev+bncBCI4ZGNIZAIRBNXMV6SAMGQEL5JM2AQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id 35FAE7326B8
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jun 2023 07:42:16 +0200 (CEST)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-18f07a9204asf396648fac.1
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Jun 2023 22:42:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1686894135; cv=pass;
        d=google.com; s=arc-20160816;
        b=PzVinEtNS1gNxvvbXx3RimCE3OGDLkI7zdleAHAUqAg1JO9snftvdfFqmCtN3gWz6J
         q+F+6CovXocQDAtQisjGoROrun3NJHY4jW0U7G5sEe6XHNVTkhiwLLjOEqP337aEZ43g
         NNrkXBzgHATJPZnzPscW+2B6KcUUaYm33+LJf/OAwQF2H1fRUoFx6DvUsFLQmJYNpmL6
         JUQEXQ5FZW/10LRBbVCgL97pmUeVTeXF8D57h/xrrICpQkaKCemKY+idwhsTxS1Zd3mB
         jKSY+DtxXoLN9Lme41l7dD3abzw4aKClQ5PatO2RCswXwkd8nIJAiD7EwzyT2VpUYaVh
         zA5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=4duRqJZWNk3i/aDNesb5oT5K+PExQmP01gCNGDQAauc=;
        b=OhjaOo5+XT+nAlsYp5uNdAyj+K0qEBdogqhHsvOyzGgjdns9+KKPDny2Mmhko/JH17
         poYNz0K+O+SuZ2iNHL0XJRtTyJOBC6kjuXFhmkE7RQO5ijnMz+cq/fpA+O3xY4jpPQP6
         Le+LyWwgSeL4MeK88Buuq4YmrX5uokFYX8CDzzu6FOl7J5wmODnkA9tlDdhOLHMHCDVY
         +Pt4tW38gp+tBXc9AvhW0d9iB5GtmohHN53qcOMjsI441PDL/0pQXJ7EpGAMuwE5+d7M
         k129E2rRyGtw/EnRGfowKYfF4To9I63HDfmi9+bixiJHGTTMF4sWEZBHWdNQeGhb707f
         TEyQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=JEkM4akm;
       spf=pass (google.com: domain of salvinokyz@gmail.com designates 2607:f8b0:4864:20::c30 as permitted sender) smtp.mailfrom=salvinokyz@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1686894135; x=1689486135;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=4duRqJZWNk3i/aDNesb5oT5K+PExQmP01gCNGDQAauc=;
        b=XS1ok1bYyyuvvB3nMEaF6zNOlnCNcBRR1eAIR51EAkxgey77E1ReWTyOox8cypJKmk
         3v/CI1pVFCpc9FELv+wI6KJ2HacwI4pVh07inSmFROePaikKIaQ56hOYr7uUv6jSAaQL
         /Z0GVoq5+m4c30+u9WabpfHW55zQtd3KAeWLtfS8ZKlXPS2bJOjGxYdRo4nrvmxphZHl
         4oKImrVvaRi4q22WIKFa2W/OCvpdSAQAWv2kcGIz/aeI+I/yjOnSYwHFqFTn4xBkRULJ
         eiAdVBuHwzEQMBrq9YBfvvDKUZp3eqA1xqHI0JPRnAoiOgUrQrbhBHnHBj7SJqlkokR6
         4ERg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1686894135; x=1689486135;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=4duRqJZWNk3i/aDNesb5oT5K+PExQmP01gCNGDQAauc=;
        b=g+Pf8Jh3WZ/xy+X8tWxA5m9WJshLdfZtCt/dnKaqUtkYhsS8xZTYpR9NJTDouVqqO+
         r3i95BwXchLk0g6qHpV1WfuaFizDcGuVKx5DM9ThogxrS4wKSkZ8/Rq+bKBozmsj56Nw
         xrFALIRbzZB1G8LTe33z8qLb+NuoKqt0HmJngxCVZwzhLax7z8ucYrWxnL7Wixrl0GZn
         xFgtVob5xzSu2zm7F82ZRZArOs9Wo9FFnbHTLlInJi+1RwKnGhT5NHqz8IhOw/fcc69n
         4wR6cb3d8tfy7STCvzpTH+hv8/aKN04/vjtYIXsG2AKpGE+vwe250/VvKRGCaYYdWvkX
         bsQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1686894135; x=1689486135;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=4duRqJZWNk3i/aDNesb5oT5K+PExQmP01gCNGDQAauc=;
        b=fQvxTL75p7+FoIT+15kIx/tpaiJ6iznfGHFHR+0jxK35ajOpzbCc7j1+/VNOXLQ+sY
         YybkcF5xLJxB1MQe2kjYnjVcXNU3qnifVyqpgiEVF+62X4ClPEUxP3bW702rE6jdAFNu
         E6a33Fw4nahd2/r0/9J0rSodLrSlYd9N59TV7Zk4MozvcYbNa+rFpsMcWCEE9QmPEN+7
         GG7JkXd7d2kH704SGTVWIXJbxQ9b+NFdocBDF/Mff3F6wjkibsL8l0IYc3m7j8JqFe61
         pkHubh5GOuZ+IrUaimJPNQCDjkIsBBLGdpIEhh8PYkCoiQkd2y15NeLaYxIQCkISaD1j
         S/rw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDzxRF5mk81W5OPFbcnaaGqnBHzwhKbXT3CKC0ujTZ9CNUdCRJnH
	LMuAottrRUuTNyHojL9Xli8=
X-Google-Smtp-Source: ACHHUZ6FcI/s8llYom7ZJueI3SsjV30sB2CNnfZuM6bAW9FlP8iKTGdSy22ZEZ0JoLdYBrBVnCnCfg==
X-Received: by 2002:a05:6870:5b15:b0:1a9:a956:33c4 with SMTP id ds21-20020a0568705b1500b001a9a95633c4mr1105702oab.3.1686894134760;
        Thu, 15 Jun 2023 22:42:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:560c:b0:19f:9b81:342f with SMTP id
 m12-20020a056870560c00b0019f9b81342fls42223oao.0.-pod-prod-02-us; Thu, 15 Jun
 2023 22:42:14 -0700 (PDT)
X-Received: by 2002:a05:6871:726:b0:1a6:4920:d331 with SMTP id f38-20020a056871072600b001a64920d331mr1559751oap.42.1686894134342;
        Thu, 15 Jun 2023 22:42:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1686894134; cv=none;
        d=google.com; s=arc-20160816;
        b=Bir8zjVVl7EtpIw0gEkR8zpN7VL4ZHDKsDVJ9/ItiSGlKKSA5AkyfYEWR1ggSO5m8O
         UjgZl3NE53Et2k7YkUSmsFmszGK/epJKAoPxwiAj/sAuu9N2CBWXfzReTsQ25D+AYyYz
         1P8m8483rwmVzBARS9WuLB9msUiFcPA+yp8JZuuZO2aEjPhTF1s0S9kgTCl7YSCR9MBq
         3WBHJdrUbveWcvIpGxd8mZAk6RUklJ1iLDplLIP9zC8PK9hfx6kNXPHSSE8P/JUzTFEu
         h7tIl8YnO4B48uUVFE8wrxiwRvtsKa9Y4rbemNEhj95a4CWYezuuu4YgB4cJJ9HvEtFE
         M0wg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=0xOCI37lq0HnnPDL8E27fgs9LAJf1c4+6s+tewR7JjE=;
        b=z5sGYCjlE/CDf8Dt1Ft0C8kelvOlRlTVzmj6gaDc6dd/LdXo7IVT3FRT5/A473jPXl
         rhvCokZA2AE7GgXlGjRz/PAgLKV2Uc9RvLbyZcQ11TqKSZ3lrRRCiY+dTWG7fX4RQ1tY
         wZIp8gMUhIjU6byC/CtdL069DVZix1kFquc+tiWbmBWt3QWF5sBvWyF8CqqVQDxbTECa
         +h/TnbQJ7swGWsIc8E6fMpYCs9HKUq/5Hphewmsh0RYYltcBJBogu65plaUROtwCLYmn
         jZj6z2RUygXTe5RGR0Md2I8YTjWs6YZCVUXnzzfQz1Ybv/aN+tuMM403XjphsA8YfxTF
         GuZg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=JEkM4akm;
       spf=pass (google.com: domain of salvinokyz@gmail.com designates 2607:f8b0:4864:20::c30 as permitted sender) smtp.mailfrom=salvinokyz@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-oo1-xc30.google.com (mail-oo1-xc30.google.com. [2607:f8b0:4864:20::c30])
        by gmr-mx.google.com with ESMTPS id li8-20020a056871420800b001a67067d94esi1067210oab.5.2023.06.15.22.42.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Jun 2023 22:42:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of salvinokyz@gmail.com designates 2607:f8b0:4864:20::c30 as permitted sender) client-ip=2607:f8b0:4864:20::c30;
Received: by mail-oo1-xc30.google.com with SMTP id 006d021491bc7-559b0ddcd4aso210839eaf.0
        for <kasan-dev@googlegroups.com>; Thu, 15 Jun 2023 22:42:14 -0700 (PDT)
X-Received: by 2002:a4a:b3cb:0:b0:558:b60d:edfd with SMTP id
 q11-20020a4ab3cb000000b00558b60dedfdmr1017204ooo.3.1686894133891; Thu, 15 Jun
 2023 22:42:13 -0700 (PDT)
MIME-Version: 1.0
From: Kyz Salvino <salvinokyz@gmail.com>
Date: Mon, 3 Apr 2023 02:20:22 +1000
Message-ID: <CAJoHdxL=iNLb4WZMnuHiFH3rZe1h6gcEnzXRhcyyY9gnR7YKaw@mail.gmail.com>
Subject: Shit U gotta set urself up for I no nun these cunts don't care about
 it and all this is for wot U think I don't know what he was doing
To: kasan-dev@googlegroups.com
Content-Type: multipart/alternative; boundary="0000000000009fda3805fe38a51e"
X-Original-Sender: salvinokyz@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=JEkM4akm;       spf=pass
 (google.com: domain of salvinokyz@gmail.com designates 2607:f8b0:4864:20::c30
 as permitted sender) smtp.mailfrom=salvinokyz@gmail.com;       dmarc=pass
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
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

--0000000000009fda3805fe38a51e
Content-Type: text/plain; charset="UTF-8"



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJoHdxL%3DiNLb4WZMnuHiFH3rZe1h6gcEnzXRhcyyY9gnR7YKaw%40mail.gmail.com.

--0000000000009fda3805fe38a51e
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"auto"></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAJoHdxL%3DiNLb4WZMnuHiFH3rZe1h6gcEnzXRhcyyY9gnR7YKaw%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CAJoHdxL%3DiNLb4WZMnuHiFH3rZe1h6gcEnzXRhcyyY9gnR7=
YKaw%40mail.gmail.com</a>.<br />

--0000000000009fda3805fe38a51e--

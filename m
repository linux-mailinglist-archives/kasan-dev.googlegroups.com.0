Return-Path: <kasan-dev+bncBCJ557OB7UPRBC52XP2QKGQEIVAHBJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F1D21C2D30
	for <lists+kasan-dev@lfdr.de>; Sun,  3 May 2020 17:02:37 +0200 (CEST)
Received: by mail-ot1-x339.google.com with SMTP id k10sf3751711otp.19
        for <lists+kasan-dev@lfdr.de>; Sun, 03 May 2020 08:02:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588518156; cv=pass;
        d=google.com; s=arc-20160816;
        b=UGzOmjarKgNfX6cwt3jDkoN826+0tlIXm//Q2LtkfQ2kJZds4VSKcbLvfLMM8iqr3w
         mRsWYDyZTXeJ6lUs5M+ryszAoQtIHfbrx2aKoOwUrtKq+bn2uOL/XRxr7aJgDB71s7op
         hfRvtrZXQpI73bidzil6AuEHlRYHFgg1LLbYG3vOHBPKzCbxYMKTuLOJZ6r40yk9Rnld
         RHdN6cQ0U8ZQCX4U0xgMszSXi0ihSLcUFrt2dc/dFZpuut55ElocnAQui4+yHxtP5L+f
         eapKbXL0GmwIkxTodjEjO0mpCNHx8L5GyKFmxRHAs+nQS+CnfIloKGVGftvIzhPrzXiy
         C9tA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=DU5iQYPq6/H/o9roWDaSvcANxmlCOrGrc+MiZGnPhcE=;
        b=1Fn1cFt87+Dh32QQQrrdPs4Ve51lMVV/y9A6cdSneXj/x0kf3OSFJ6BK+bPE3ct9o8
         cG9HSit8TRwkzZvHPv+lWpANl0YhNc3aLHwMhZ9Qt8O8/eXRfGd10bLJ/StFmb7o+KbH
         4FnuonTXCJE1puQ3oIQsk4jMgGIwZfSpxJS/k0jDnxtr91nZbzuBm1fF1wvlmvXxa7cY
         +wBNtlxNdXofOqGLiG1XIM5ScSa7k/9B71OnsO52wlnFpMsRBt3wXbURWqNNcdwzHIFO
         5mLv/C8wA0yh5rlJiQrRxEFugNmE+I0SRD4a+3FykcWch8m5IdC/yJ+PCQwFty5Qv7/B
         tyVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=nQ9unaGc;
       spf=pass (google.com: domain of siregueye690@gmail.com designates 2607:f8b0:4864:20::142 as permitted sender) smtp.mailfrom=siregueye690@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DU5iQYPq6/H/o9roWDaSvcANxmlCOrGrc+MiZGnPhcE=;
        b=irgfxTvi7LTN5qVF9cyQYumSYwY19h8UNr6+u7HBffGJtI47XQqJLbqGoN9PVe3DGF
         ubvua5JNj8F/cYgkQkpw0LhOFYajCrmLASklTVvPsUWGoSY5h1oqqPQB/4QH4AbK0Kbc
         PrdmgZ04dhxqtqdd7uES8B2I/YR9TnGgRJRj8ir/OUYNnSEcVzMVjcAVOnJqKOuTuhPs
         QxxM83p9NEBf+dJ52yWKrsnW2qFpbxn7BaHByxXFWzU/Kp6QfO0lcUeRDcqnE1mCkd06
         HjhL9e1pLF9xT67JLNjSjqxbPX2Hu/k9spHogR4R8RHiAIZRynPApW5hvoArM8Tpt2uE
         t5pA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:from:date:message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=DU5iQYPq6/H/o9roWDaSvcANxmlCOrGrc+MiZGnPhcE=;
        b=dbf2+Tdk4/EnzVWz68p/oPp28tWIlCr1kE7AQESxXx4pm8QNJW/AzCpOdIHecCZmvB
         zsU9yfv3WM4Uzt5mX1W47QTYizNddKwSivfOThePfAhqVRMdz0G/DVESQf9YtWF3UC2Y
         J1AvAyMuOfVBmlx/1bYrSP6FuSml5Qd/3+gwIaEhdf0hw4I41l8E2OBql7ijpIeEZUrI
         z3PHXY6Xor4WKtFzTc1KYtB5ZpN1WPWC5EcV7pi3wFXHjUoEudLCJfwLtK0/aMuvpM/W
         BGDVsMTnxCw86PHBeoFqJK26QEfjHb6r+8TjnOrlf7OsUTkJw1T5VUsaaKCDXA9BZld/
         YEvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=DU5iQYPq6/H/o9roWDaSvcANxmlCOrGrc+MiZGnPhcE=;
        b=E6b0d/TRfQYDWEzSuFu1LfyKF9f+bKXH2sK0Oy25QqgPMfcbJSTrxSKux5eDBTFMCK
         vS6/micZUN0SAmkkEJJ6mLGFa6H9Y0B69oLaVu+0b509A2Ts74TeFAc2Z/X1TAnA+dy6
         dNBppc8N0C9aJZN9yhPNIfw+0/cVCWKLuuCZOze3go+l/n9nfwXoXBo1dH4k+e2kMx10
         eAbBucX6gqho6zmCKDu+VLWR4ROgBav+njfDQuGrhLdcCl0cXsX4kve2O7o6oqGH7Q2d
         A5WuXBCKBSRoPhtRED1JAi6aBx2MVot5GzJD5m97R+i7uomi22xa5vWlZu/kteYrLKXK
         CzAA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuZM767XofKdVUrkWxfyMtp0YLz69Qcfs9C2hlfRdYnWqEmQtq7C
	NYfM712qgVLweffpHUAzMi8=
X-Google-Smtp-Source: APiQypLxBHL30XrsUfDT1xAdah7KF1cAZR5YDXiFGGvsYCDyJ9opmv6Kadv08toQaDdZgbuSr4ZB3Q==
X-Received: by 2002:a05:6830:1e7c:: with SMTP id m28mr11003048otr.12.1588518155894;
        Sun, 03 May 2020 08:02:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:4d0c:: with SMTP id n12ls1641485otf.7.gmail; Sun, 03 May
 2020 08:02:35 -0700 (PDT)
X-Received: by 2002:a05:6830:4db:: with SMTP id s27mr3758406otd.301.1588518155616;
        Sun, 03 May 2020 08:02:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588518155; cv=none;
        d=google.com; s=arc-20160816;
        b=JyTmOwpcG+RSSZctXZfo3bM6TqUujFHpMIkAJLftMAZlZmVqf7xaD41AvxVX1xc4o6
         gQBZTsPRYpjEnu+UZXvKJUIXX9kJ1QeL1kuihaE1/YD28/np92mJsUd7n2r/pT9ThSDC
         7eZf47nGuwx4w2e7/HHgtuFudwJeNF4jl+/mA0kmyQzMHrCamywLKhMQUPxiVAkkIxY6
         ZtHoLmCRFVLSuBFpjmN8Itx4DKFUr5YhgNaWi3HXOYTW0DGD5LaNagvaXObUI0Rx0tjQ
         FsqchUaEZlW8JfRo/mLzNkK0zLMblyeFGcCCHIzJZT0+V9XIHZPBL0+PW+oEtleyy5oV
         aVeA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=AUPFVebkMCP2d6yXFLiX1kRiXR3fvLCGSwVbHCCnyec=;
        b=xFs+P2Wl1QCoX2NR5hO/rpyWnb/no0u0s/P6hRqMXgO/HkZnsXal+J9w2jynAtELQt
         FhGmk2XSu0jiLGhUtSQEW9ej3kC0jhLbiGgqFQoH9kFmjENsp8XPcrZSovWMhgd9R9PG
         6l8Fw1abXKjdcfbvMIrmUYJCULITywGqi9t8dRCFH48kHtf2sie1trnzYPtQPhUXgMzG
         HxWfftLQ5u/K96ORKE+FtAN9QH4prcawJ4MX5CHlIkMYAibAgBHz04FUDGeGvmDg/xSP
         fDjBoouHAuf8sktWWMzvYHhTfDU3m62QsxPO87VeqHvTdFEO2Kp3Sosbxc12+KVxJXbI
         +z3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=nQ9unaGc;
       spf=pass (google.com: domain of siregueye690@gmail.com designates 2607:f8b0:4864:20::142 as permitted sender) smtp.mailfrom=siregueye690@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x142.google.com (mail-il1-x142.google.com. [2607:f8b0:4864:20::142])
        by gmr-mx.google.com with ESMTPS id r1si470558otq.5.2020.05.03.08.02.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 03 May 2020 08:02:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of siregueye690@gmail.com designates 2607:f8b0:4864:20::142 as permitted sender) client-ip=2607:f8b0:4864:20::142;
Received: by mail-il1-x142.google.com with SMTP id i16so8903793ils.12
        for <kasan-dev@googlegroups.com>; Sun, 03 May 2020 08:02:35 -0700 (PDT)
X-Received: by 2002:a92:89d5:: with SMTP id w82mr12029591ilk.153.1588518155393;
 Sun, 03 May 2020 08:02:35 -0700 (PDT)
MIME-Version: 1.0
From: Amelia Ibrahim <ameliaibrahim520@gmail.com>
Date: Sun, 3 May 2020 16:02:25 +0100
Message-ID: <CAGtvjUjJKyhVkgQxwt8zSDkEdhaRORAy1tVH-YW+8EThc2Vemg@mail.gmail.com>
Subject: Hello
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="0000000000005f1dd405a4bfb412"
X-Original-Sender: ameliaibrahim520@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=nQ9unaGc;       spf=pass
 (google.com: domain of siregueye690@gmail.com designates 2607:f8b0:4864:20::142
 as permitted sender) smtp.mailfrom=siregueye690@gmail.com;       dmarc=pass
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

--0000000000005f1dd405a4bfb412
Content-Type: text/plain; charset="UTF-8"

 Hello, I will like to talk with you

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAGtvjUjJKyhVkgQxwt8zSDkEdhaRORAy1tVH-YW%2B8EThc2Vemg%40mail.gmail.com.

--0000000000005f1dd405a4bfb412
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">=C2=A0Hello, I will like to talk with you=C2=A0 =C2=A0=C2=
=A0<br></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAGtvjUjJKyhVkgQxwt8zSDkEdhaRORAy1tVH-YW%2B8EThc2Vemg%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CAGtvjUjJKyhVkgQxwt8zSDkEdhaRORAy1tVH-YW%2B8EThc2=
Vemg%40mail.gmail.com</a>.<br />

--0000000000005f1dd405a4bfb412--

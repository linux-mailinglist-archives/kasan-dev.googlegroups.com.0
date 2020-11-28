Return-Path: <kasan-dev+bncBDBMZ2XLTUEBB7UPRH7AKGQEK7GFZKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id C40042C6F83
	for <lists+kasan-dev@lfdr.de>; Sat, 28 Nov 2020 13:52:14 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id k128sf4325616wme.7
        for <lists+kasan-dev@lfdr.de>; Sat, 28 Nov 2020 04:52:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606567934; cv=pass;
        d=google.com; s=arc-20160816;
        b=jdmUk3O63dT1M1dgvOTze9wEi3skc9UKa9x9yXDcxVdQMZF46UUWMYqKuHHhT5h15c
         rh0rXo7Itmdi4ZtCGf5kUCfI34HjezQX2Hn8yFAztmIlg3C919+7wpmHuWvqA182AW3s
         7u/mZcyyTeUQ3O9hJFfkPI9g05//N2hWURe16iY+wVKESKIEQS2D9jJ7SeYuUKJkpHEQ
         pOL7MONn4s8toHMbLvIUhWAOyHUmGUupyGRGc7hTyUcpeAV4G1S0WAl8DSL7tghq9lzI
         o+2EKVT+PoZEIJvP8ESbjCzsvXmwglK4Bp4TAqyKLMOdkK/4U8jkiS/wX6DFMoK0GTdb
         RKNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=Uz1L2F5XfsnYLe7YfOlQgpZo6IcsMU/1jrssIZszELE=;
        b=jZoAX3FqVuUbeMZ2uSEWZRo9C/dTfcverEQOYxfKGsaauQX+dPzdE5XspJmjDt1WR9
         Hip1GS6NdQbqdpG0KxW+wEMudwr2llGcntoJfBy27X8OvlBPobbN8Zxpr4IjNlUTln4+
         NUJWBEPRQuSpfpHsDufnB+xfP96RbSIaRf7C8rvPXKngA8v4Q9D+eY1dCF1yifgjDkgc
         YPqhKJZ+wezT71l9D0mPGefgCTLjTl3zSptWgekAmSg2YLsL10KRZyxNicFPKGLz72IL
         2CGB62+6sqdmD3x6paPMWqypTCdRz1hHG2J0+TqOD5ksCBnO3pchMW4T5byp2o5DMs6O
         MPNA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=qZbdIKNt;
       spf=pass (google.com: domain of amathiame52@gmail.com designates 2a00:1450:4864:20::635 as permitted sender) smtp.mailfrom=amathiame52@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Uz1L2F5XfsnYLe7YfOlQgpZo6IcsMU/1jrssIZszELE=;
        b=n2FWKiN2QYbZM+pRaDLE4DfPnsbshILkAUAxkqviXBDg06iW4Jo7iRoKXvzZHsiwgq
         uxQXDhMm+4/RSK8k278ZbgsMqekrsaoI7OsHHsstiqZslPKxnY2n2dyLFExYLuL8+UUV
         KjdfRBGU5aQwD7SgMHWAkrWeSrHbMJHPJ2Mj+r4rZa+tRGiEWdRBgAPPcKXyp0Rb2W4b
         ojfOUl64iQaG+II5IyRJo0crt3eF+NQV/JWe41A107bzuOwFoZZGokiS9YSeddgYOt+c
         WgKvYNoiFxfuN2mEggZaW9/UeMrjq8grjOOiRiTAmm/pENgf7iZe6y8Mpr8bVNkR2jGW
         1Mig==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:from:date:message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Uz1L2F5XfsnYLe7YfOlQgpZo6IcsMU/1jrssIZszELE=;
        b=apwCPobZBfiWtloPk9A+30rdn6ekf8UuZxRPpAtQ+8+LXaNZDB7aG4uFw04fk1LWJX
         WN80esn3QNPlPCn9ewzhLqfQZjm2zNbrJAldXWViUmLq/H0TVG57kz7h5ZAgYeXBn4IN
         D6fUuNWpARhkhM5P1M8Db7abavcfkGZpjPLfXbpPCyn73nmCRqDmmHoplj9rF3jZCS3E
         u4xwL5UZ5uExZgLikltav+ksj5pVTCZcTJGeMujBDy8m27qrQg5nOsQUAG7oyyfe/dt+
         iWwCfLTOh2DY6n9aaqPAaKt8aW39HqKqzhevSU+VUiJuNIhHXEbFS22PbLhGYAL700eP
         tFDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Uz1L2F5XfsnYLe7YfOlQgpZo6IcsMU/1jrssIZszELE=;
        b=glq058eKXaRXUXN2D/5ImG6Tn95SUhdUscll/+qiEXZ5Cl3RdR+evOehUIfBwZ8qnW
         s07N6S3DhuDQegY0xjm3CylcyW7j7Yow54Hs36w7ClVKLgqRq+5pcpPUQ+OE8cMedXRq
         Hpf3aGuNW3PhOQCZdxpt1ExuFoz7kB2afbOKLhZCy1DklN9HbGEJ6GJ6yJD9NUCsh2HV
         Cw9PJ5y8qRCPSmTTVZbesdHETp8cvmNUiAVZpNKRyAAjIYy+MeAYWUuvpztcypzJ/Xcq
         qKp/jcosgmGHQj/yaOlL/Q74Kp4ZInchzLEiCZmmNUB/yYDfL8OM1QtWieT0zzgMEF7q
         2VTw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530W3ovL9gb3E35Srgtu4hK92P2jDpbMbztgPWlr7jI25YNnwLx1
	TmoC11XEJ3GSQHFc5R1+l2U=
X-Google-Smtp-Source: ABdhPJxT7y7OvXoFEWGUoSaABKWUme/nSWdORYQd6ls6GPHqTRlpaqWW5UnTzUM2wUKlbJ8ccrEyyg==
X-Received: by 2002:adf:9b85:: with SMTP id d5mr17485615wrc.9.1606567934532;
        Sat, 28 Nov 2020 04:52:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e5c2:: with SMTP id a2ls3150707wrn.3.gmail; Sat, 28 Nov
 2020 04:52:13 -0800 (PST)
X-Received: by 2002:adf:8521:: with SMTP id 30mr17381426wrh.265.1606567933549;
        Sat, 28 Nov 2020 04:52:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606567933; cv=none;
        d=google.com; s=arc-20160816;
        b=d7GuKxzusu6NPAU1HMLfMV+wwujhiT4I9bKMJPbHGhI4Af87egwETkSJsIZzKGGNQz
         J3EJvVS3lKfLF2XtotoHHYUJk0WZEVTF8pvirh28PsB2aU6ckdoNPaNZYLZqroMl6Hro
         uYeQtG6F0OOWTHczZMEwbf+7ygZdSixro0PnrQMy9hVri9IHXOevm0mkGL6haL65cfRp
         /BzBvcR6v2vBgqAfL0oIy5mxrXO6JQfPpGewNW8E98E/3COBqlU670mmbAMfMKKsJfwh
         87MGib6n82rFFjZlWnZU+zInGMhcjx6/MoSHY+A2JAyk618lunxxaNVdQDAL8B/9+q5o
         7Anw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=rnrpsmB4+VpkWYFxX4RJz2uCszQ5Q0Lzu7mkij9cbjw=;
        b=iJ0nII/6lyEZmyy0Q6GGcDZ8esZfTuo8zbwFVITQr/JZbrJkw/PvkyOe6hqY3lD2Fw
         dRSxw2hXIFylgEOQHRM113YZzsAUNx6IkRw4pa5r0zcDRGGgCvJDrD2bCzVi+uNKAeJJ
         oXLEari8+Gbo2X6wXy5BMXRTGaIzSjWkjDmzlyKIgrb26Pz/uxRtJdm69YIq6IHRKMn1
         M8koL0r8senPeJ+bSpMal87zf6XJpV92FU9HTzCuLEwxLiGhUE2CLueDJ0Ls8d9JpSgt
         vV2brFaafbnKhPWXp5KHvW1YrUPoc4QROeuPYL6HEUtfGKMVQ8WkNKO6u0EvAL44C9n6
         ovCQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=qZbdIKNt;
       spf=pass (google.com: domain of amathiame52@gmail.com designates 2a00:1450:4864:20::635 as permitted sender) smtp.mailfrom=amathiame52@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x635.google.com (mail-ej1-x635.google.com. [2a00:1450:4864:20::635])
        by gmr-mx.google.com with ESMTPS id z83si590127wmc.3.2020.11.28.04.52.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 28 Nov 2020 04:52:13 -0800 (PST)
Received-SPF: pass (google.com: domain of amathiame52@gmail.com designates 2a00:1450:4864:20::635 as permitted sender) client-ip=2a00:1450:4864:20::635;
Received: by mail-ej1-x635.google.com with SMTP id lt17so11482191ejb.3
        for <kasan-dev@googlegroups.com>; Sat, 28 Nov 2020 04:52:13 -0800 (PST)
X-Received: by 2002:a17:906:3d69:: with SMTP id r9mr12664141ejf.43.1606567933298;
 Sat, 28 Nov 2020 04:52:13 -0800 (PST)
MIME-Version: 1.0
From: Jennifer <jenniferabdmanaf@gmail.com>
Date: Sat, 28 Nov 2020 12:51:13 +0000
Message-ID: <CADcC-NQq8EzOA_mfZwG5rWHtUUG3PQYuKZgnjNEMDJ78v=LJvw@mail.gmail.com>
Subject: Hii
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="000000000000f8cd0405b52a3e32"
X-Original-Sender: jenniferabdmanaf@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=qZbdIKNt;       spf=pass
 (google.com: domain of amathiame52@gmail.com designates 2a00:1450:4864:20::635
 as permitted sender) smtp.mailfrom=amathiame52@gmail.com;       dmarc=pass
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

--000000000000f8cd0405b52a3e32
Content-Type: text/plain; charset="UTF-8"



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CADcC-NQq8EzOA_mfZwG5rWHtUUG3PQYuKZgnjNEMDJ78v%3DLJvw%40mail.gmail.com.

--000000000000f8cd0405b52a3e32
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><br></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CADcC-NQq8EzOA_mfZwG5rWHtUUG3PQYuKZgnjNEMDJ78v%3DLJvw%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CADcC-NQq8EzOA_mfZwG5rWHtUUG3PQYuKZgnjNEMDJ78v%3D=
LJvw%40mail.gmail.com</a>.<br />

--000000000000f8cd0405b52a3e32--

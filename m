Return-Path: <kasan-dev+bncBDAO74OYQ4CRBAWPXW4AMGQEFUDLFNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 923439A0236
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 09:13:08 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id d9443c01a7336-20b61ec80a2sf65886965ad.3
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 00:13:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729062787; cv=pass;
        d=google.com; s=arc-20240605;
        b=Jzo4/4cNocDpeOFvdyTASABYtVCDrXiSsyq18CD5uzV6iqeYMNWK0kKxQYsj17Ndh/
         lEUaIVa0UIBml7gBKldKQo7nRlPA8DLzkTyYCvwXsRvtHfuv3MPEzsyI40BdCPs4DiKc
         S7IGxoamt9atny6jb0iQQEqSKsbaHfi/L/Op0XKuwV/aOIVFU2GE+u+jUO6DE+f9TGim
         CCRcX2+23z/SQmzTPSzJnt+YQ8M7ejaZJMwGxWwGh44NZU/O43PLhCHMKaCM/eojcq+x
         iC2MVslMwDBn+i0KlRofLgdwsltC/KOaBQsi/+Y+hzYG6CeHdzqgIzYzQ/BoHE+Ge11f
         EyyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=q7bBVRorh5+UAgPs8lVCdDGn4biqIUOahdmPbmnSJxg=;
        fh=Lp1hAOuI82nxVrgCUrvK6u/pn0qFzeswgHxXKe5CVpM=;
        b=Ry/tf/LL2/0LCiRgLs2J8GFCgiTBYeJj+BmUlXaQ/67/HdkCylpS8A3SEwn0J3iWOZ
         P+tMfdr9tJfIMvrrryWAEN0YD3mjN+rCYa0Ekh6u25sg0lRakffPMThpuhmQ5x4IDTfd
         7xuUIq9r8GIO1V4G5If2tynk25uI3gxzY/7Rl2D7Pj8z1qaQ+qRXnbRnf1OJz2SNT5PX
         eK+SVNUDQ9E74S1SbDbrnvpYQ2HurIgROdcQOfXI6FVKf3KQh+9rCbmv0xvKEsxIqmHv
         WPUeLfulpM8Xx4gsdoAJpwesFU4tRky6eureeLHcQ1wbYvHWUIbT1EVFq9ffzjCc+QBa
         auTw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=cupS3dyD;
       spf=pass (google.com: domain of johnandy001470@gmail.com designates 2607:f8b0:4864:20::933 as permitted sender) smtp.mailfrom=johnandy001470@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729062787; x=1729667587; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=q7bBVRorh5+UAgPs8lVCdDGn4biqIUOahdmPbmnSJxg=;
        b=fc94WAp5ADGRcWMp9HihSkcHh5eADj4a6++6nR90ipJA5jLfD/ktNMtB920Kp2tZTd
         0rAUVPKzoJnrtbWgoTX2XjDGDjbWTYfWgE45krwz3YGVry3PevUG1LEitqO0ptozGEWa
         5YY5axhaGZ9zyauAM+xcaffprCHD/rOYS5DZW4fD+RN+oct9OpWL7lDCH/rMHkqs6IhX
         d+2dTpqzP0nxClXm4CKQEuu/8O4QUlmQHZ1CcSmTt9wGW3ECPAYsy2xX2+cKdZMEjILf
         o6qZLKeYvGvT0bi3No2O9yxhGEM9zD7S+e+eMcE99RoLuH2CpvSyu8e89Z4uPKt3lVC7
         Brbw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1729062787; x=1729667587; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=q7bBVRorh5+UAgPs8lVCdDGn4biqIUOahdmPbmnSJxg=;
        b=Y1c5NukRXzvNL9+1ZNKN8zLsi+Mu4QB1Hay9MQQfiK1X1ZQnV0vSZqHrKM66Q7gnVv
         JoC3SnoIDWvMKo0ONqyPcit/TCh+yL0zpH8ZHOjXXBpgowFu0C6NPPiNDcdK+iXFPYO3
         BVFQuFlp0DNnu3AqYd9GAA+jZTyF9ImNj+DPBgZOnU81xg7+jymDsbOg2cHMmXIcwWWR
         uW4Ue76WfcfEFEAF17TbScZNKgm2ruOF6ksEFo4w9u+08pfNiZ2ns1GjCaGWrvWV5M/i
         /uhQVgyqZEC0llcj1ZzVUqfA6TQUX3+WL34uLinIDLKfAXIzdAFS/L/F3++N1msR814X
         NWog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729062787; x=1729667587;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=q7bBVRorh5+UAgPs8lVCdDGn4biqIUOahdmPbmnSJxg=;
        b=Ku3Pw9O3aKwQxhP7t2l7udnofJjiCb4Ot+DuNUGy2/KJozIvqsDyXhYLegFLoUKL+7
         8y6m9crtO+uc81rejjRtnNSHkmEQwsTCLYNTv6Ry3dFQAY6tD52BG7f7lBYUKecyUQXI
         79tICfENBCmlC6s7juRx8OgOzWg0rlyD0QymZR2I3xRbxRdXa31Tt2cVKU97j6RM+jcs
         ZGHVKKt3h1KDnhA3UwU8rT8J5oes308VdyQCOMOAbaPcNcWMXAFNmGmeXUn83d8zIYyK
         CUVVYHWXr1GTOjKBhPTriZYu3U/K3StfpT4r5jSDjfUv/3QKjFmaHKZtMhyP75LlYGzG
         vqrA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUEo3VwDeecc07Hb3uaAQcNcCB+yWiGiGZ49fvsRz7un7R86rUzWCggZ5I4wPvh1YNRYmTfhg==@lfdr.de
X-Gm-Message-State: AOJu0YzlUdHHnGh1sndClk0nQ+G330E7ZlcPYahMJ5ur+wL+JXXOI7g+
	BozcNGEEA+62s1nk6iCUpa/O0H/OAY96VksctFXgHYpha9pU7Qft
X-Google-Smtp-Source: AGHT+IGguvUp+c8/66Awsqh0EfGYpzwzeeRKZ5v7jzTHfWNM9bltC9+Q2tuN6cHCok3IOBTQqluSeg==
X-Received: by 2002:a17:902:cec3:b0:20b:5be:a403 with SMTP id d9443c01a7336-20ca1429594mr237660255ad.11.1729062786656;
        Wed, 16 Oct 2024 00:13:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:f64b:b0:20c:7ee8:fc58 with SMTP id
 d9443c01a7336-20c80a9ce09ls54930135ad.2.-pod-prod-03-us; Wed, 16 Oct 2024
 00:13:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW3Cy6S8PUFRyDHa0rXTgxmkaY3VBNxvNWYiGaafYuu8UryjXtjewt2WFWmLeD6ISYdTmjKAZWbcTU=@googlegroups.com
X-Received: by 2002:a17:903:32cd:b0:20b:c258:2a74 with SMTP id d9443c01a7336-20ca148bf3cmr222319285ad.29.1729062785407;
        Wed, 16 Oct 2024 00:13:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729062785; cv=none;
        d=google.com; s=arc-20240605;
        b=b69JavSaL5Lp0mS8SbprRDVVzbpmxqTWR/7CxEKwr1ELXpgUbMJUE8gXJ+Sy/1yrKN
         FKcXJwhacD4aJL0sbP4sp2F8G0Ww3uV+AqkyzhDANk598uBAEUkPp6Egj1kxaL95LEB2
         vb+fEyB6FeBUotMo42WUXnD7v4uOkJZz9xwNt/jbevlOwFSjqVIBEIIat7I45b/A8bgI
         tBAN5//OgWRdlq2RvxrT5LSqG7u68d7+A7dprVq1W3TBO9lxI4DVmepiepftfhcXh997
         NOX0ADrh3jbvze1Uhlup3tTMS/h8JyQipePs48PHU03r1NeQwfvfCS192eLkp8ZfvnKA
         d5yw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=s6BdsIHmFJ2WmiaZX6IJkWVtFxPQMfNS9fIRe8i/9kE=;
        fh=0JPtPbi/N7K05610/FqLy6DMNL+N9AsWEevvHCrYx6Q=;
        b=WyjhFsfQg1v92INzkeMsT90+UY7RP8ojoo/zfcMpG7uWKQ5XvVN2s7OrdgEVRMKTVD
         q0ILkf9hJgVl+pAou0hBkUwLLliwNyCWt5DUlO084OpWxgCZgQ2boU9yONLcLRzIJWqr
         7x5HHsCbGxhFoA7Awz718ByRSJH+5tyZu3GTYH2BsRs/LoB1VNmis3bjCfYTL65XnRtq
         v5VaiMnSga/iLuSD+HVuFyrrp6iKj+i5r4gy71uJZ0Tzm5rMdjDRSHBhViOrhDm9qEWy
         afIY1SSXhKgQZCQ0nm2q68ZevLoJLVtCDZ4emACF0GUUltPI2I6UVn29Qc5UnydCdBg0
         HSFA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=cupS3dyD;
       spf=pass (google.com: domain of johnandy001470@gmail.com designates 2607:f8b0:4864:20::933 as permitted sender) smtp.mailfrom=johnandy001470@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ua1-x933.google.com (mail-ua1-x933.google.com. [2607:f8b0:4864:20::933])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-20d180b4e3dsi1326365ad.13.2024.10.16.00.13.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2024 00:13:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of johnandy001470@gmail.com designates 2607:f8b0:4864:20::933 as permitted sender) client-ip=2607:f8b0:4864:20::933;
Received: by mail-ua1-x933.google.com with SMTP id a1e0cc1a2514c-84fc7b58d4dso1733574241.0
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2024 00:13:05 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU31lzsHFyooxMfIwqtlgChmXcFYmTefk36jVsYN6iks0yfuLC6DjJqv0ftDP/bjDVJHsheAY2F4vQ=@googlegroups.com
X-Received: by 2002:a05:6102:3ed1:b0:4a3:d46a:3590 with SMTP id
 ada2fe7eead31-4a4659604ecmr16842412137.1.1729062784253; Wed, 16 Oct 2024
 00:13:04 -0700 (PDT)
MIME-Version: 1.0
From: john Andy <johnandy001470@gmail.com>
Date: Wed, 16 Oct 2024 08:12:36 +0000
Message-ID: <CAE56iV-KgtJP89evoxCTp-bm7YP_rVCd+ig_fYTxgG=hs--w5w@mail.gmail.com>
Subject: Merhaba
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="0000000000000cc7d0062492cd56"
X-Original-Sender: johnandy001470@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=cupS3dyD;       spf=pass
 (google.com: domain of johnandy001470@gmail.com designates
 2607:f8b0:4864:20::933 as permitted sender) smtp.mailfrom=johnandy001470@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

--0000000000000cc7d0062492cd56
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

 Merhaba ad=C4=B1m Miriam, senden ho=C5=9Flan=C4=B1yorum,

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAE56iV-KgtJP89evoxCTp-bm7YP_rVCd%2Big_fYTxgG%3Dhs--w5w%40mail.gm=
ail.com.

--0000000000000cc7d0062492cd56
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">
<span class=3D"gmail-HwtZe" lang=3D"tr"><span class=3D"gmail-jCAhz gmail-Ch=
Mk0b"><span class=3D"gmail-ryNqvb">Merhaba ad=C4=B1m Miriam, senden ho=C5=
=9Flan=C4=B1yorum,</span></span></span>

</div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAE56iV-KgtJP89evoxCTp-bm7YP_rVCd%2Big_fYTxgG%3Dhs--w5=
w%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.g=
oogle.com/d/msgid/kasan-dev/CAE56iV-KgtJP89evoxCTp-bm7YP_rVCd%2Big_fYTxgG%3=
Dhs--w5w%40mail.gmail.com</a>.<br />

--0000000000000cc7d0062492cd56--

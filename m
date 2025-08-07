Return-Path: <kasan-dev+bncBCS2JKFIVIEBB7HN2PCAMGQEFWH6XCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 85F73B1DD3B
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Aug 2025 20:57:02 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-4b081d742d9sf47794731cf.2
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Aug 2025 11:57:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754593021; cv=pass;
        d=google.com; s=arc-20240605;
        b=gBhmL/ugEdiROFqLFd28tH5b1bzF0vd2n/L5CVDzpcDCxB4aSpGmvprLcMwFKwZbIx
         TqttOdTlmJOrQXrXV3CwUztsRzEoua+eacGih7RsXOKTIxwRfBE3Bl1R/vh8FL1ZXGY1
         4yvHRaHVj+5lYMeUiS2Pz+KL0HeiWI2XJL28bbqTixtMTDcZbUbfrgzYByiVNFs6ijFz
         L67Hgfb/m6LGJySJ0xnU9Yw4SZq05/rkBP1eXdSj0Xojcem6pAn8nPbO4SYr4udZZkfS
         02g22pHGFap4L3EFRXWKhYIK7ocC3NXyEpJTmOwEE7p+K7Q3rXbU/U/tbiLbB7jjRMtw
         0gqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=4UsN+OlFrJH6RBIUZw4k2JxzVgVljlwcwQYUfevJcl0=;
        fh=I5hZMBfh/Ny1xaOQXLo4dqJ97IOOaEkrnvDbn7g1NjM=;
        b=MX38f/QlvwhftH8tpKFBKR+63edeH6DD8KdRZCVPGrcloECGH+5VtVjLwGaajFn2Ye
         GQ+gLA483Iaj0/PRHJkSrXaaa/z2nVRGaBrywdEXek94EpxNri3bm7xr0AUGobHKubYt
         54HRr0HEnYIoFnBAUePBW4ZyvW9cGXa0W325PWY18buchqC8/C9PssQJbk/FXTR9kZZF
         K4GPoksyoAJmVhiU1636YUZMYGKJqS5bOdrZYK7TdDiUy1uJbWX07CVs4JIge0cWPdBW
         Ff5wEJdB72I/L8ry3GNV8NadYYaqrP6N//Vfjnwd+l70zpvvizpht99p4sZSqYVFohjO
         D7gg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=gPNqhxP9;
       spf=pass (google.com: domain of phains391@gmail.com designates 2607:f8b0:4864:20::12c as permitted sender) smtp.mailfrom=phains391@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754593021; x=1755197821; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=4UsN+OlFrJH6RBIUZw4k2JxzVgVljlwcwQYUfevJcl0=;
        b=jYYdruMB2TurSDHWaZZCXlLpRR3pPRrvqAj6xsEHgXBDoDJcdUOe/Xfo2xc3QLlRyq
         l/F4jENEReLd6BTzYIvCvik/17T2xIvPhJ+z5Ya4ItmJahYxi4zoE/XvxewvB0/JaYAv
         Co96K3TYp4jIK/JbIwLS22JJn4f8ujIKxcv21U6sarsf5A+VAehyjE1GJp+zDIcsYJsw
         zac6zO/xF8KOL9Rd6xGKMpyvglbshQGGO2hLVT6nRXZSI+/oiaI1Tvznb9EGceAjANzo
         Z0gktWNMw+ndQGF0kjaGAypiIbKwsbmz0KZbq+tRz4SItwHyqnBbXeDRL+biZR0MLrYW
         +/uw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1754593021; x=1755197821; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=4UsN+OlFrJH6RBIUZw4k2JxzVgVljlwcwQYUfevJcl0=;
        b=FcFSRd9Xy7BW49kfILOfSG0dRSTybo1UOfIJgZkl86ivbFVnJbZQ8pFkGaUNi1b2N6
         os/n0YUpS3NdDOBZG6RA8tjoTlmVS2C0YoW1uAecckmJuZ0DoCUlFp4hqPJkL2ilxZfm
         t1rka8hJt8naeZk454/H+4cm3lvPutM2d3oBXbInkSOSlI0JMkctVym+gwT59yP2TkuO
         DOYxhEAo4Hyfng1R0keOXQnqB479wxzU84/HNGSg8UE+3k1uggIgB/kpHu/6jmrVhfZh
         MTOU50sm4pipgL3pnSjFvmXunNW4n1dZNL2T8HRPl4oXJHl8rsFQnTJceQf2diD8Uw36
         Li9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754593021; x=1755197821;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=4UsN+OlFrJH6RBIUZw4k2JxzVgVljlwcwQYUfevJcl0=;
        b=HK2eV5I1mogzXhVv9rrCj3Xh+8W8MRVtp/vvY+R02dPzLs0JXALFBN/g0T63t1xlUp
         xuiQMu3rathxgX6pXABP1pZ9+YXk3QukA1/d9R+RKGrkirIttg+xDXpeKcnIwKi7hoIt
         tANAV8tvfuSTBwjgDymBHVMk733Udv3btUFGDrWnCt/kAcPeWKP4kYHtthWCcc511Siu
         lhph9YKkqapv31KTJs66xqkYtK29r/rbMRFQN5TThYt5fbvs/9mne/bZ8lwwAToNbbAs
         rxXvFih05IeTdbYKg8qgVP6J/ejDiNFttvFF9Szygv6MZ9d/HNvLJoH7ZJFEsjwWXGPX
         1qcg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWwSacWz8pB6EnKbNgldbRgN/iU49ZDg4qFYr6UDZtm6SH1FWGbCUhD0eNFOSJ3fweNDdeMrw==@lfdr.de
X-Gm-Message-State: AOJu0YwIhmmn/3NMcXhW4q52NelaGCX9IRyXW8zEwAf9P9fYEI9jdEe9
	4FBhZSO+U+4hWb3NdYdnA7e8GoTZ74Y7o9GTFWMFILcMU0QTXinAEngn
X-Google-Smtp-Source: AGHT+IG6U6/5n5MJAFZYO216ps4ieDBbQHBfU10u0LA5Mcyb0GStVa6SE8yGeXA9Wr28pHFu+dUzCg==
X-Received: by 2002:a05:622a:2b08:b0:4af:1fb2:339b with SMTP id d75a77b69052e-4b0aee5ae32mr4864561cf.59.1754593021099;
        Thu, 07 Aug 2025 11:57:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfNb0ZPLJceVzStsi12TARCRfX3XzK474o9guAjqQgyeA==
Received: by 2002:ac8:5891:0:b0:4ab:9462:5bc0 with SMTP id d75a77b69052e-4b0a061729als20677871cf.2.-pod-prod-06-us;
 Thu, 07 Aug 2025 11:57:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXeu25ApeHmk48MY/8MKkE1kqjIZJna2JoS5yZrXH41teIePv341crBOqyXdF1azywZJNPSjV48BBg=@googlegroups.com
X-Received: by 2002:a05:622a:2b08:b0:4af:1fb2:339b with SMTP id d75a77b69052e-4b0aee5ae32mr4863811cf.59.1754593020101;
        Thu, 07 Aug 2025 11:57:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754593020; cv=none;
        d=google.com; s=arc-20240605;
        b=lw6a9bAd8nB0dl46c0RSCu9MQRQl6zPEovxg/eTtPkgkcF9vIu0UitX9K/M8uNmIR1
         FGpcRwNjN2Cjr83f5mkWtJnjXl1FWSy8aW4k5rb6qK2bvSOVQ457UUsV4gh+v9QJxFcx
         vT8KLHvWvCG3PLWXHy4BcQhWg3zyWmhCzBj9hCtX0NmpwOBOqT7EyBaqbaDznCQdNwgZ
         qu+OApO5mv/piXGpC3cIaU4IY0GQeJi3sqreKRMtJBzgvTUTADK9wU9s2+jgJn4pPv8t
         H6Jt3Z6lZYNZL/jH6E+XPp3u9xWVTBpg2qv6V4oevrc2ZIgcexGNVh/s7Lgcppe1lDwd
         GdKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=nYrnP/KiJo21Tii6q5NnGJpZf+VcfZqSblcQJacFd/A=;
        fh=xHmXcG8kUfbxZ7hzYEYPgas5mWM3/oy7Cd0ItIaLNEA=;
        b=f481YB1lBaKKKuriadOdvneq7jVC5iuH9Id71I9o9dtkn6ocNUKpbIu4MLb71g5HSb
         +mPMGo2XvfeZc043LejNDQF5iKXVwlmvxxlyVk/KWcnx814ca72f/yZETymFEqGiStzF
         g4ce3uNog7Cb9eFS/JpwmuV7d8g7w+3g3QUb4b4+2QJ85YmVuJ0H64g1GCiZpFadkj8s
         Rxf3UXpp7KhhNWPkbqRNMdb5paWGVth5dpsa00xoqDfArm9NyaT43zVriL48yguFlsBt
         6Ur35lfQJSvjRN/blZx8wzrMw+gWkcGqZBGD6jrw98V4o5nCO1+kcwwMPrQgVQ6gCwNP
         XDoA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=gPNqhxP9;
       spf=pass (google.com: domain of phains391@gmail.com designates 2607:f8b0:4864:20::12c as permitted sender) smtp.mailfrom=phains391@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-il1-x12c.google.com (mail-il1-x12c.google.com. [2607:f8b0:4864:20::12c])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4aeeebd0825si372261cf.1.2025.08.07.11.57.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 Aug 2025 11:57:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of phains391@gmail.com designates 2607:f8b0:4864:20::12c as permitted sender) client-ip=2607:f8b0:4864:20::12c;
Received: by mail-il1-x12c.google.com with SMTP id e9e14a558f8ab-3e5328231e6so506665ab.0
        for <kasan-dev@googlegroups.com>; Thu, 07 Aug 2025 11:57:00 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXqmZZoyeGUUhm6Tuo+7quwUwVIYIzBVMQWPuuWcdPm8wEnvN/Ma7Vn6dmFbgipidZc9hE/epTyAPs=@googlegroups.com
X-Gm-Gg: ASbGnctykn6qqwzf2/Ak98zP8pq9aatjNCqGfyefNXuCKAUIg0YHTadLKmXutfa1wsb
	WKG5I8UEi1bN7VakmDCXc3X8rRw0V/aBixC0gv5CfwIF3uy7ozU4Rxy3ijUqCd+0oHLS/17OYvw
	YjHr0O85Eo0c4GNkvn+xPoX58QWEaEXwgaXx+JnKRR+8wtUqFXhtgNQQ1jdlFVdNv3/9rhk0pC6
	wjiwwUocd+7mA==
X-Received: by 2002:a05:6e02:1aac:b0:3e4:2ea:bbf5 with SMTP id
 e9e14a558f8ab-3e5331cbe10mr3963195ab.21.1754593019296; Thu, 07 Aug 2025
 11:56:59 -0700 (PDT)
MIME-Version: 1.0
From: Paul hains <phains391@gmail.com>
Date: Thu, 7 Aug 2025 19:56:44 +0100
X-Gm-Features: Ac12FXx2J2S53xCcayfVGT1YBkydoIIPBVexyPSYJu-qfjoTNdLqSnDjA8UcD6g
Message-ID: <CAPFLb+ZooUQEhipnM2qgL0V4Xi=DoCDFij2xE0tB9wG=X=EbqA@mail.gmail.com>
Subject: Dear Friend
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="000000000000a407c1063bcb05c3"
X-Original-Sender: phains391@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=gPNqhxP9;       spf=pass
 (google.com: domain of phains391@gmail.com designates 2607:f8b0:4864:20::12c
 as permitted sender) smtp.mailfrom=phains391@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

--000000000000a407c1063bcb05c3
Content-Type: text/plain; charset="UTF-8"

From: Dr. Paul hains
Director Bills & Exchange
UNITED BANK OF AFRICA.

Dear Friend

How are you today? I presume you are healthy, and if so thanks be to God
almighty.

To give you more introduction about me, I am the Director Bill and Exchange
UNITED BANK OF AFRICA i was the personal account manager of late Engr
Bernard he was dead on 5th Jan 2009. Since the death of the deceased,
nobody has operated this account till date.

Now I highly need your assistant to stand and contact the bank as the
business partner of late Engr Kings Bernard and receive this fund in your
bank account to avoid confiscation.

And I would like you to keep this transaction very confidential. It seems
that I am still working here in the bank and I will not want anybody in the
bank here to know my involvement in this transaction.

The shearing of the fund would be 60% for me and 40% for you and I hope you
will be satisfied with this shearing of the fund.

I wait to hear from you as soon as possible.

Best Regards
Dr.Paul hains

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAPFLb%2BZooUQEhipnM2qgL0V4Xi%3DDoCDFij2xE0tB9wG%3DX%3DEbqA%40mail.gmail.com.

--000000000000a407c1063bcb05c3
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">From: Dr. Paul hains<br>Director Bills &amp; Exchange<br>U=
NITED BANK OF AFRICA.<br><br>Dear Friend<div><br>How are you today? I presu=
me you are healthy, and if so thanks be to God almighty.<br><br>To give you=
 more introduction about me, I am the Director Bill and Exchange UNITED BAN=
K OF AFRICA i was the personal account manager of late Engr Bernard he was =
dead on 5th Jan 2009. Since the death of the deceased, nobody has operated =
this account till date.<br><br>Now I highly need your assistant to stand an=
d contact the bank as the business partner of late Engr Kings Bernard and r=
eceive this fund in your bank account to avoid confiscation.<br><br>And I w=
ould like you to keep this transaction very confidential. It seems that I a=
m still working here in the bank and I will not want anybody in the bank he=
re to know my involvement in this transaction.<br><br>The shearing of the f=
und would be 60% for me and 40% for you and I hope you will be satisfied wi=
th this shearing of the fund.<br><br>I wait to hear from you as soon as pos=
sible.<br><br>Best Regards<div><span style=3D"color:rgb(32,33,36);font-fami=
ly:&quot;Google Sans&quot;,Roboto,RobotoDraft,Helvetica,Arial,sans-serif;fo=
nt-size:16px;letter-spacing:0.29px;text-align:center;white-space:nowrap">Dr=
.Paul hains</span></div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/CAPFLb%2BZooUQEhipnM2qgL0V4Xi%3DDoCDFij2xE0tB9wG%3DX%3DEbqA%40mai=
l.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.c=
om/d/msgid/kasan-dev/CAPFLb%2BZooUQEhipnM2qgL0V4Xi%3DDoCDFij2xE0tB9wG%3DX%3=
DEbqA%40mail.gmail.com</a>.<br />

--000000000000a407c1063bcb05c3--

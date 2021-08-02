Return-Path: <kasan-dev+bncBAABBIFNUGEAMGQEE5ZC2EQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 66F463DE0BE
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Aug 2021 22:33:37 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id h39-20020a0565123ca7b02903ba26e9bc4csf1979166lfv.13
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Aug 2021 13:33:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627936417; cv=pass;
        d=google.com; s=arc-20160816;
        b=AhSHFGYJRakaZqe/YUnEbqS5BKxRSr6NL/G2BQvPUFWCqjMjhREPCr5mc9dYOhD32U
         8v+0hIENRvZGoVf6b56cBr7PtkLKrK3wVFzOqKoux93TEWrYvorFlrhzHabyq3fi7YZo
         y5vLCXfXlZQMmC6HuhDYVBlLWpVE12+f30HFVnRQcX2fhdTJ+8Qo4iJDdcjQEZbmceGA
         TC7V8KgRD1RKEfBdPJ1pOJk5viV58Rh1gL790GFSQbKEljfYNFwFy8sK/k9O3D7aisKF
         3xL6ZlsFv38kA16RwnMKlPBNXdybz/8k6EVdqd+i46+W2vNOLkva3MniEgGvPwRqxkwN
         aFNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:subject
         :reply-to:from:to:date:dkim-signature;
        bh=FvdsnIvm1pFW/TS6NPwTU4bNfZokXUhhtBXxuhiUl+4=;
        b=nL6Xv2BXwzXT/H//jvV4eFKuK7zBnSa20lgs/h3x1QFvSW0pUTaGUE8sWxV8dueUTs
         z4UMYNlS+023cFHrREj4sxaQGSzRZeK1nkrJPm/sUqNhtV2swuvKQprfX7PZD873BMGM
         jn5qGYAwXWdT021+2vCHZD/MWW2WeK+Tw6SOxmdw6xsSR1Qi/ENV6Vby02m0lR41AJN8
         3ECtt1xu79u1Oo8VLqyV7qcQTK4pnV9VkkjIZZFf7R3ea4Yei0I5zD+1d2mYNaOXyutK
         BAPm6Zh9DJmDMiv+A9/0i+K2wgKzNjG+OkJKzp6pw//Uj2yj7xltUepT+lT9T3IBm0EB
         lkYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@protonmail.com header.s=protonmail header.b=icJV0Rne;
       spf=pass (google.com: domain of nerdturtle2@protonmail.com designates 185.70.40.27 as permitted sender) smtp.mailfrom=nerdturtle2@protonmail.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=protonmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:to:from:reply-to:subject:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FvdsnIvm1pFW/TS6NPwTU4bNfZokXUhhtBXxuhiUl+4=;
        b=JYiJ1CooYYlSUZmxSocq8Bl+h+2QexlP0cGD1+4oYxMu3fU4wjASy/7AqG4pZzWGcj
         p0J2m3K+tkXhdp8VajSUACgXvNEev3Yyi4/hROkNL3JNxJViAZJfy9Zz6/jOHMpAJLie
         ARiRG6jMfSne6ACq5yWfzmNm3ttcSPSeADerOrF1YgJlYAca/Zesc9wYJ3LqJbbAL/IX
         IbySbDMmgBnkeBQF0PQmgrsXQRfS8Nnpk7t9kdw+xIde8PWgTbvcbi2rX8iA7ztI76SX
         DZqYv8wTkyBHwnW0VZlcABrI4rgJ4zNoopclVVLod58pMDtsPIb97E4/uMtuhxBD+nYB
         +Qhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:to:from:reply-to:subject:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FvdsnIvm1pFW/TS6NPwTU4bNfZokXUhhtBXxuhiUl+4=;
        b=qdWEkX8JzHtjM7O3GLQB/kU3Qj3EU4i0t50BhQvVwBUFA3eJ1+xE6sGQnTw2LPZF55
         BEYp/AqUFxG6ZINf6+pjtrXH+sgophYP4wU4E6YstYB5dEV/IN//pubpPzqMZU689PCD
         dWHoTYYokSWV7C0pkGDS7Vxe9eR5miy9JqTzue4TuZ70FEjCpKZi1DfipgNDKuFFcq8U
         0sIiD/oRRedJBz/HnULWu9arR4ca4LX4+v+0Mdx+vqi+YPtYJWWOr8rKZpCE0Wd4cobV
         4/M1/+O3P9EPUEDRgj7OItFHkout+lP9Tkw3w7HiNdkBGb8XquvMZxcDw1TvWwGuIJk0
         sstw==
X-Gm-Message-State: AOAM532F0zsHiQNcHmx1G9VY6AUc1jpuh0BO0fKU+S9sLwfO7VWUhYAN
	Q+X45fFqxyLyFFKjQyYaxvQ=
X-Google-Smtp-Source: ABdhPJw/um0AI5xouwntAYGOvVRFg7Q3AvhFmz2at/H76RLfGBZu8pkdKF65RbzCsssZA+FLI0vQVA==
X-Received: by 2002:a05:651c:542:: with SMTP id q2mr12357835ljp.192.1627936416990;
        Mon, 02 Aug 2021 13:33:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:88c:: with SMTP id d12ls1707944ljq.9.gmail; Mon, 02
 Aug 2021 13:33:36 -0700 (PDT)
X-Received: by 2002:a05:651c:113a:: with SMTP id e26mr12207699ljo.373.1627936416124;
        Mon, 02 Aug 2021 13:33:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627936416; cv=none;
        d=google.com; s=arc-20160816;
        b=zKLR8hrdASljMjVB9FWtJzHyaMneYj4aIhR+cwJtbaR+ipUFc/6jz9A5NmpPizgiCS
         D/Pqdp4HT9G1iJbR8a3+aYznzOikMHrnLzAC6VQf29MsgdaiWCfqyt6IJl8pNI61mUIv
         QJSkfCyxU5Cevaa9lUqQZAU1BJO8Dr1YyxFXZ+wFQSCtbNJWkXwC5MQ7DGPnnJ33zhH4
         yxTelL7Enid+YuSYfTvoW+trWU9TdWXci8aY2w/ynma48ONKGJZoBz7rJ8t2r+gar4OJ
         qHidV/1zc5WPmHmsbvDZOX0UXq3QR/W0RFweLAZP1RpAQgxsRLke5R6sEFT2jgrNi2US
         UzXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:subject:reply-to:from:to:dkim-signature
         :date;
        bh=qEq2Txk8FZvjsRwcBKIBUu42wVTV++RR3Bn0baI/1iQ=;
        b=LzdhDCItvsCJwekKeNbPzBOq6F2vZ5MRd3ad345kCmqZTxzLH1pFbL6JnlEIwSZKmC
         QTFJJ+85hf+UT3zXtiQCgId6/tFhD7+0OPNo0ByNqJ48a1YSV6NHtpB3d+v30mNO+oQ9
         MikNzv8Dr4kMjmzrlrCTi3a4GrBb954fXPr3ppOABViI78hmYBRJlb5GkV7DB2OKZCZZ
         vjk2eICkfpTIVlvSEvCDo04WfvtpmjnvYkMxOisgSDYqUtpjQ2rbE7Gqt+yPrYDv2x5F
         esBQxotzNqpUfN0Sbu6ZHNSRi8gIhv5fX6JEb5UoymuH4sSP+NIpOly/rjZIHm5sbkLd
         Dtaw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@protonmail.com header.s=protonmail header.b=icJV0Rne;
       spf=pass (google.com: domain of nerdturtle2@protonmail.com designates 185.70.40.27 as permitted sender) smtp.mailfrom=nerdturtle2@protonmail.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=protonmail.com
Received: from mail4.protonmail.ch (mail4.protonmail.ch. [185.70.40.27])
        by gmr-mx.google.com with ESMTPS id i12si719756lfc.10.2021.08.02.13.33.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 02 Aug 2021 13:33:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of nerdturtle2@protonmail.com designates 185.70.40.27 as permitted sender) client-ip=185.70.40.27;
Date: Mon, 02 Aug 2021 20:33:33 +0000
To: "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
From: "'Mike' via kasan-dev" <kasan-dev@googlegroups.com>
Reply-To: Mike <nerdturtle2@protonmail.com>
Subject: Enabling KASAN On Select Files
Message-ID: <bWmJIaBTNCVY08GLY-AFFzLkFRIWs1NxOLdMGyWgELKsksOzGEb6Q0-wWCYHrLMJmqM7rxNIRA5mebViNUXT8czz4KAgyGhmXCoKmtE_yqw=@protonmail.com>
MIME-Version: 1.0
Content-Type: multipart/alternative;
 boundary="b1_QUVKJghqc7Dq9ZuKf8dSBRWm65J85rtr7Nxe7Fx3GE"
X-Spam-Status: No, score=-0.7 required=10.0 tests=ALL_TRUSTED,DKIM_SIGNED,
	DKIM_VALID,DKIM_VALID_AU,DKIM_VALID_EF,FREEMAIL_ENVFROM_END_DIGIT,
	FREEMAIL_FROM,FREEMAIL_REPLYTO_END_DIGIT,HTML_MESSAGE shortcircuit=no
	autolearn=disabled version=3.4.4
X-Spam-Checker-Version: SpamAssassin 3.4.4 (2020-01-24) on
	mailout.protonmail.ch
X-Original-Sender: nerdturtle2@protonmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@protonmail.com header.s=protonmail header.b=icJV0Rne;
       spf=pass (google.com: domain of nerdturtle2@protonmail.com designates
 185.70.40.27 as permitted sender) smtp.mailfrom=nerdturtle2@protonmail.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=protonmail.com
X-Original-From: Mike <nerdturtle2@protonmail.com>
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

This is a multi-part message in MIME format.

--b1_QUVKJghqc7Dq9ZuKf8dSBRWm65J85rtr7Nxe7Fx3GE
Content-Type: text/plain; charset="UTF-8"

Hi,

I see in the documentation it states:
"""
To disable instrumentation for specific files or directories, add a line similar to the following to the respective kernel Makefile:

For a single file (e.g. main.o):
KASAN_SANITIZE_main.o := n

For all files in one directory:
KASAN_SANITIZE := n
"""

My questions are:
- How can I make KASAN disabled by default and just turn it on for specific items?
- If I add the "KASAN_SANITIZE := n" flag to say drivers/Makefile will it disable KASAN for every driver in the kernel or do I have to add it to every specific Makefile for a driver? (eg driver/superimportantdriver/Makefile
- Does the "KASAN_SANITIZE := n" recurse down into/take affect on every files and subdirectory in that folder?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bWmJIaBTNCVY08GLY-AFFzLkFRIWs1NxOLdMGyWgELKsksOzGEb6Q0-wWCYHrLMJmqM7rxNIRA5mebViNUXT8czz4KAgyGhmXCoKmtE_yqw%3D%40protonmail.com.

--b1_QUVKJghqc7Dq9ZuKf8dSBRWm65J85rtr7Nxe7Fx3GE
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div>Hi,<br></div><div><br></div><div>I see in the documentation it states:=
<br></div><div>"""<br></div><div>To disable instrumentation for specific fi=
les or directories, add a line similar to the following to the respective k=
ernel Makefile:<br></div><div><br></div><div>For a single file (e.g. main.o=
):<br></div><div>KASAN_SANITIZE_main.o :=3D n<br></div><div><br></div><div>=
For all files in one directory:<br></div><div>KASAN_SANITIZE :=3D n<br></di=
v><div>"""<br></div><div><br></div><div>My questions are:<br></div><div>- H=
ow can I make KASAN disabled by default and just turn it on for specific it=
ems?<br></div><div>- If I add the "KASAN_SANITIZE :=3D n" flag to say drive=
rs/Makefile will it disable KASAN for every driver in the kernel or do I ha=
ve to add it to every specific Makefile for a driver? (eg driver/superimpor=
tantdriver/Makefile<br></div><div>- Does the "KASAN_SANITIZE :=3D n" recurs=
e down into/take affect on every files and subdirectory in that folder?<br>=
</div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/bWmJIaBTNCVY08GLY-AFFzLkFRIWs1NxOLdMGyWgELKsksOzGEb6Q0=
-wWCYHrLMJmqM7rxNIRA5mebViNUXT8czz4KAgyGhmXCoKmtE_yqw%3D%40protonmail.com?u=
tm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/ka=
san-dev/bWmJIaBTNCVY08GLY-AFFzLkFRIWs1NxOLdMGyWgELKsksOzGEb6Q0-wWCYHrLMJmqM=
7rxNIRA5mebViNUXT8czz4KAgyGhmXCoKmtE_yqw%3D%40protonmail.com</a>.<br />

--b1_QUVKJghqc7Dq9ZuKf8dSBRWm65J85rtr7Nxe7Fx3GE--


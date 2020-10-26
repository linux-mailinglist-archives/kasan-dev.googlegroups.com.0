Return-Path: <kasan-dev+bncBC6ZN4WWW4NBBDXT3P6AKGQESLFYOJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id A541E29926B
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Oct 2020 17:30:07 +0100 (CET)
Received: by mail-oo1-xc3e.google.com with SMTP id r25sf5917228oop.0
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Oct 2020 09:30:07 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:message-id:subject:mime-version
         :x-original-sender:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XFcTjei5YzzqXTCWOrC3KIw1hgcheynqfG3yi62y47Q=;
        b=Y2xE7GEfxHrKPhaHvxsPiruM4/ag9JH8kTf9m+/ATKoW/Heb4ndRRWB2kZaN2BjpOC
         ZYe70KKqUid/0gP5nO9hxOxWm5f1z6ZKxHWfQpEdFu7qBluCdeH2sPlX7Tf4luV0g+AZ
         MzZaCBQlYfPxxtJoPx6Gdm4IhTocFc60OUvOBsfil+t3OVdZaSEF7at3qU+9m0UeHe9i
         vFyIKVHzoIrUFQ/AiEkuPU8YrKxw5DhCL4Jts5do07WG0tPPO9RqBlE/sRdo0iIuw1nZ
         cLl6KTCe6EbkHqWG7WblbiNyCVLOk+E08l49d9y+KvWOeKwEaNWv7idh2h7zcDCAHTav
         HNzg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:message-id:subject:mime-version:x-original-sender
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XFcTjei5YzzqXTCWOrC3KIw1hgcheynqfG3yi62y47Q=;
        b=SHnwOm4AB6wjsFjjkQQ1zMgpBJI3MBbxfM3hmuRZ2LJZ/jlJlVlVOc9x/dP83XCmlz
         U/pNVkTjBEQw3IunNnnPy33cClirZW71hWXTjMv2M2726tE2sMSev3YVTd4FBDROwQcA
         HaFWCajSiqg5yadMt6uSehCV6pAJv185c06o6Nx3Po9nJ1f2W5NhI5Xt5JIocBtsDli6
         uubsWjKyygW4CmOw8pFIZ/oDwAFcj297t/prCL5qBeFadHsDQUmfXShnMYD1y0FnNdKc
         O/vsa8bOTWDAynjEc68PFsaRuOHBpHTOGdbxYNP+dBM2NZv56FPNDR4tuwDWSox8DDlB
         tK0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:message-id:subject
         :mime-version:x-original-sender:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XFcTjei5YzzqXTCWOrC3KIw1hgcheynqfG3yi62y47Q=;
        b=bMpX5t1jaDDYol2dswC9+OpdqYS8YVr86Kj8ddX3WPlv1RuMw0fIgb23365vhA+/C/
         jyPSBbufoUTgEhWxb6N+Jv0ymiL5SItFsWPbgxEmvJna/ZE+MOuIxiSPA7q5591/CWw0
         Fy8JbTwltvLreFLS+KyRrGZrdGzsaw+SccP4p32y9ga+WJS1p6r7fqmTZC6KUoi9VCug
         T63eGSx/yrI7SvHK8rHvcQKllbsww26+qXP5f15Ix1gTOnhFqpXeMp9YmDVELZt3Dl/T
         5chCeH7ncrkq366xiW1ww+LM+nK5ML+88Wtlynu2+yUgS589y1IBSCiDlQp/elhhQYSQ
         3BMw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5334haWQ+dPQwmchdn/RBRsJXetQlo7O+VBrXBgkPjNFQlgMbZRN
	C2/5MlUuBEo76xjVSlrAoog=
X-Google-Smtp-Source: ABdhPJxOHB95MwPyL3EvtWx4HWKG903pkZ9fCTQHEuE/z7hROp6KdfScDx5kvEjbfVGRdjN0FnHcVw==
X-Received: by 2002:a4a:ba10:: with SMTP id b16mr14213602oop.75.1603729806293;
        Mon, 26 Oct 2020 09:30:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1f59:: with SMTP id u25ls2288812oth.1.gmail; Mon,
 26 Oct 2020 09:30:06 -0700 (PDT)
X-Received: by 2002:a9d:6005:: with SMTP id h5mr11459509otj.87.1603729805869;
        Mon, 26 Oct 2020 09:30:05 -0700 (PDT)
Date: Mon, 26 Oct 2020 09:30:05 -0700 (PDT)
From: Jidong Xiao <jidong.xiao@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <fbb6a417-0767-4ca5-8e1e-b6a8cc1ad11fn@googlegroups.com>
Subject: How to change the quarantine size in Kasan?
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_940_236441080.1603729805194"
X-Original-Sender: jidong.xiao@gmail.com
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

------=_Part_940_236441080.1603729805194
Content-Type: multipart/alternative; 
	boundary="----=_Part_941_1868714472.1603729805194"

------=_Part_941_1868714472.1603729805194
Content-Type: text/plain; charset="UTF-8"

Hi,

In asan, we can use the quarantine_size_mb parameter to change the 
quarantine size. Like this:

ASAN_OPTIONS=quarantine_size_mb=128 ./a.out

I wonder how to change this quarantine size in KASAN? Do I need to change 
the kernel code in somewhere (mm/kasan/quarantine.c?) and recompile the 
kernel? Like I saw in mm/kasan/quarantine.c,

#define QUARANTINE_PERCPU_SIZE (1 << 20)

Does this mean for each CPU 2^20=1MB is reserved for the quarantine region?

-Jidong

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fbb6a417-0767-4ca5-8e1e-b6a8cc1ad11fn%40googlegroups.com.

------=_Part_941_1868714472.1603729805194
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Hi,<br><br>In asan, we can use the quarantine_size_mb parameter to change t=
he quarantine size. Like this:<br><br>ASAN_OPTIONS=3Dquarantine_size_mb=3D1=
28 ./a.out<br><br>I wonder how to change this quarantine size in KASAN? Do =
I need to change the kernel code in somewhere (mm/kasan/quarantine.c?) and =
recompile the kernel? Like&nbsp;I saw in mm/kasan/quarantine.c,<br><br>#def=
ine QUARANTINE_PERCPU_SIZE (1 &lt;&lt; 20)<br><br>Does this mean for each C=
PU 2^20=3D1MB is reserved for the quarantine region?<br><br>-Jidong<br>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/fbb6a417-0767-4ca5-8e1e-b6a8cc1ad11fn%40googlegroups.c=
om?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgi=
d/kasan-dev/fbb6a417-0767-4ca5-8e1e-b6a8cc1ad11fn%40googlegroups.com</a>.<b=
r />

------=_Part_941_1868714472.1603729805194--

------=_Part_940_236441080.1603729805194--

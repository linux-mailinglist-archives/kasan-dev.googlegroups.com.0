Return-Path: <kasan-dev+bncBAABBF6E5G3QMGQEMBN6D4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id 2283B989CD0
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Sep 2024 10:32:25 +0200 (CEST)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-2874aca0e13sf850531fac.3
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Sep 2024 01:32:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727685144; cv=pass;
        d=google.com; s=arc-20240605;
        b=HK8p0K6L8XV0nMMopi2XsSTKXyflApPgw12hCNPE7KRU7m71+pd/b/jfG8YfmXfDs+
         FzfONf2tfBMXq1mUxTDf0qW11HhJ2yuR2fwVkyftzb8T3FarP6PJay1ZmjKB/jLTNmcf
         UiE4CJmqrt7bDJ1Qy/WrZtF/Udd0P0xZm65mz8ihsrmGs/RLd/mDg2EqZRndvlc2Sn7s
         4sG5VVFpQMeNqedqw0JjihPhjWtEDq/HQKyVR0H5UTKclwKjVfabBN5lLn27aGpFUTXk
         Ypf/qzIT7EpW1liFW5U7OaoD4KblcBsv1S7kn5VF1SyTZx66cIlXMRxDKq0/QeO+VmUD
         /nCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=NfHyiY5vR/pUQXruE4v80CQZQ5JCTRBEskbpBgSvsIY=;
        fh=qsR9iQ2ZKB8d6iy1LH7BotL7sidTQoyAhDsFQU2m7JM=;
        b=k0tdibp8yXI2XF6XEUW8vvE9lcpdfOQ5hEeK0Y8xr7qrp6mZ2A5wmIU9gRNIgu/djS
         jTKLGedY0OMMSkB8cPHGT//1jB0HOnToLsMD4kJhvRzuSRYeAUnmT9h12in0rCCGEm1X
         2vg7UFrOd6F0JuNGCFNPldTzGnXTslGF3rZaGLgk60bdY1Gvyk5g6o/Q4HNbzVQLNlzw
         QBKJd0NVJ6bs+SxYVZYkv/PmVVvRpiF7lxZqa8SMqfgdX5r0WKWa3HW24fJeK0s+Y5Fv
         6MPORO193V7L2pJnBXF4N1JXZNrXssP7xBRkSSbk4AAULGymPJI4lwd+HpiVLBhAYrSS
         uwow==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=KUl+sZD3;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727685144; x=1728289944; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=NfHyiY5vR/pUQXruE4v80CQZQ5JCTRBEskbpBgSvsIY=;
        b=hkCbwoOjwqp5ELOL76XlgCbUFi28Pp/QWmCFhPU9VamAM1kBcoavMt0tbGls3TFxQQ
         h9NgvdVUjsbZPFaJSLC5FZIuJjiePeuKO3tAaDnN5Fh+JibTRbYBHN1GeMXbijgan3pZ
         BHGRn3qvRxphvr+pKH5D4lrGrQhrAtexg+VJTqautOUulEXKanpQRf50cX51R8e8yuOI
         AmU0VVtpTX01T0jy5r3z6W2DLI4XFLokO0ecGUrB4s4jC18tsmEQmeuSLrONEACu4QSl
         vVDB35hy6h+iq6szVakFM3uIUwFhyoFh5zaRXyPEo7laz7oClsKqcfvx8mq1hyaBhcdK
         Cy+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727685144; x=1728289944;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NfHyiY5vR/pUQXruE4v80CQZQ5JCTRBEskbpBgSvsIY=;
        b=FbVkA5gWRf+k1hPvZa/70tdwKRhnSNEB+pzpUTvWHEGVqPgwIT64XqzU9w9R/OhwU3
         JXL/a1bdTwbrf1zFjsjCaemm4AHzJyGFwUePKFTsm7v7dFxGeNdfwRvHdUEZ/aSFrSFq
         +dv6pTiXdATCaxA+o2knDdC3yaSctOK34SCtoM03PqK9KJ6Qgr+0jW4OjlUaihBnEKw6
         bDXqTZ4ikwytC3GEf9GuUux+W8/VQP/9kNi9qdO+kYj7fGyVqlVUnmNGAbV512kV0J9j
         7gC99a4X7T7tj+eyoI/JStk8AD4Hl34FVMfVMHvoWJskWTiw4LhkhqnEDsESprMQ4L3U
         hxUA==
X-Forwarded-Encrypted: i=2; AJvYcCUOJj2Lo7kko/iAWUarDUTkSkXzR5fayF+OOyUyEs8yGyKgLA3NHI1e+EJhG5GaU4mw09Lhmw==@lfdr.de
X-Gm-Message-State: AOJu0YyUGgsK2qxSYdQkr0keaLX3yfmG7vJRzTdnUTMgEv3l7/zZQjLp
	yvOy44OKgj+3zpWwMwosnmLQnznHvdLFvfAk7kdyqInkrV18qxe7
X-Google-Smtp-Source: AGHT+IH1XNEogzC/2c2LEpAq8uen0yE0EESStvEpn3PyxiH6EN7cvv24hrfDA+M9ayFpIXXvEf5DDw==
X-Received: by 2002:a05:6870:c18d:b0:267:df02:f7c0 with SMTP id 586e51a60fabf-28710bd1115mr6060488fac.33.1727685143716;
        Mon, 30 Sep 2024 01:32:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:3149:b0:25e:1ff1:3bb7 with SMTP id
 586e51a60fabf-286f8af3ed0ls2070557fac.0.-pod-prod-02-us; Mon, 30 Sep 2024
 01:32:23 -0700 (PDT)
X-Received: by 2002:a05:687c:144:b0:287:3cf8:4abe with SMTP id 586e51a60fabf-2873cf84e0emr1883048fac.18.1727685143043;
        Mon, 30 Sep 2024 01:32:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727685143; cv=none;
        d=google.com; s=arc-20240605;
        b=TTZy46ZE5EQszU95kZsnmbt00v9arX4g1YtcrGVyF8333pntBQAlYuLv/j+XPapB7Q
         iK797zX6DfYfIX6oYrVUOdzz2GFBcvGjgk09uLCPpBc/tMptgTB6Oc3/HE2n46m9RR3J
         avFfliGF63ZlyWYEeOhiyQfX45o/ucnUJAGz701Pum7fLYRh1ChCz7MQFSGVP6tqgz3z
         b1I6Y5/1eWfz28285AC+3/ebFsSKitJDIR7ZALm0aeNqFmsGOWSX3mld9wMFisNqKm5y
         o6pAKngbFNebNQ6bsTuj2h5bgKgfX7dzjATVvZDSxtXwGzhoirSXvHhcoE3I+1bvAJ8z
         oqBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=aLPig2yUewpdUtLcUbgNnZ3pL5Y8kvPYiy0aIgvIZUQ=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=Psnf0bHLmrupzLf0FKi7/jzQCO/ubyEcydKk9a1xOqODW+wOc89e0MaRrUMTqqXmy2
         +fHuto7pUQ/QtfaLHrLB1qpVuBUWLuguiqbo9TTJvEIJ1q/zvOBNm+WKr38ycLFhFcAa
         Rf6hjGZdyTXcwU1zxfYppxDDrth21sFes29HYriEvhiCFIbR5z1PV8cuMuIoHgtTUd2e
         dMXksgjWIuAaBYds3sff4IvKXFuX/kV6CS/HpA6XT8vedeLZ64qempCVsIdE4LMR8LUQ
         MDU/hjfuRbdtReB2R0Zd2de1mhTN0lQ+ckPeRyEAxY2iuMjrpyjLqAa6ky01RAsEh29V
         eLbw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=KUl+sZD3;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2870f9a25dfsi317976fac.3.2024.09.30.01.32.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 30 Sep 2024 01:32:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 23722A4168A
	for <kasan-dev@googlegroups.com>; Mon, 30 Sep 2024 08:32:14 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 1C30EC4CED1
	for <kasan-dev@googlegroups.com>; Mon, 30 Sep 2024 08:32:22 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 14D1CC53BC9; Mon, 30 Sep 2024 08:32:22 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 210505] KASAN: handle copy_from/to_kernel_nofault
Date: Mon, 30 Sep 2024 08:32:21 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-210505-199747-J9hZhAvErn@https.bugzilla.kernel.org/>
In-Reply-To: <bug-210505-199747@https.bugzilla.kernel.org/>
References: <bug-210505-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=KUl+sZD3;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: bugzilla-daemon@kernel.org
Reply-To: bugzilla-daemon@kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=210505

--- Comment #4 from Dmitry Vyukov (dvyukov@google.com) ---
The patch will soon reach syzbot and it may start spewing lots of false
positive reports. There is no config to disable this feature, so the reports
will happen until a fixing patch reaches all tested trees.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-210505-199747-J9hZhAvErn%40https.bugzilla.kernel.org/.

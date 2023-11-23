Return-Path: <kasan-dev+bncBDW2JDUY5AORBI7Q7WVAMGQE2ZNDFIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 6037C7F6387
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Nov 2023 17:04:53 +0100 (CET)
Received: by mail-io1-xd37.google.com with SMTP id ca18e2360f4ac-7aad53fd070sf151864539f.1
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Nov 2023 08:04:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700755492; cv=pass;
        d=google.com; s=arc-20160816;
        b=cJn65suxxEcsgGlC96YnoHQyQn7tppJyF9gUcX8bjkH5dxobFEjdUHxRF7lm1vA4fz
         xQ9iBC566BSu/KlfKrftsCoiaeyk0+1CYEiTpImS7Sxxn0IG9TjoD+fPj1SaCPxoGeSg
         TraA/8d9zTLmEBPVbtiCPuxe4Kj8/vJCTRjHqDe5zhKRcZSV2kfEhZrdYy/Wn86a0zWT
         LvvtLk/VZb5uQ5GoqDkfSieww4olejnF2B0upTy71XQi2KQxHpZne6vtZMHmntoJI47f
         AwDvB6hsphQdpWWAyYrAotHlAeBdk4NgRN7SSsOJiHUWHqL62nFkvj6PjlqiPVrkvFkS
         rjNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=BX+uMKMKffnBqLzU4kZQxO55bPQEday30GkLDYF4iAg=;
        fh=sY3wElV5VHyiE/pHU4Rbii9LrO/Ppek15KCMEaKn7XA=;
        b=mAYEZ4v1hxnCvsiMTKxXwf/Y3I+OCONPHFA3NmSbZMtym6kQIdYOswQxHiuwfsoMzy
         2igyvdL5Cxt8Cbl/Ml9YqeJcBqYC0yvstjRpvYbk82gXUr0QeUIpyUgb+jPmuB7uxx/J
         T/rRM4U0UyAE6oan4IMaANcJqHLrrQq+yqQ+KhGTwDTM8bA/1BnW+jQVzLn+E8jsJM5P
         JaUPc0xpHyQm0s+PZWWC8T6OBYTe69OshLxCqheB33ZScdh4l4B4zOTTcxGJYZf5Ui1r
         Mk4u7AMjbKmJ+iH8Tz0OMjI8hC7dKccntJryaFI6cfvVe5TUwHh+x9jewtDe/nikKNVW
         yLeQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ihQKFzf9;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f2e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700755492; x=1701360292; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=BX+uMKMKffnBqLzU4kZQxO55bPQEday30GkLDYF4iAg=;
        b=HEXrms+692lGJ8a7+5UIcq4TB/Or3BTQStwASts690+eEt1EKs3bWSPL91HfwehNfr
         odZVHBmpd0YjPfbBUlrlqDDRSgKumHcEG+7q64U2+PSU+jNSnNKCCYXUU4ICSdtk0tQC
         3e7cyKAbDq+azhUuZWEtBiqJ7FKvxvxESKi4oFKwVjgIVNDVEDOUWVUMzQ8A1TDNTbQ+
         gtEBZwLEiPMRytOAHfs9JtFsIh4C+Uc/4aM7vl89xwkMBbCcQYaWtydaUi0E1UL+zVeC
         Nmu3imz+hQJRXD2C1ADkzrXZhx3kpLw/a8+TWBKBlZBYprEaPVp4zoth+KX+TVqGUTkk
         zQgg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1700755492; x=1701360292; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BX+uMKMKffnBqLzU4kZQxO55bPQEday30GkLDYF4iAg=;
        b=K8F2j/XQARssC6zJUEJYIyTEiIAYhKQBovIJd8hNucn25cXbzk2MCGCn2sFeIm+mas
         HTo6d9+SuNrjGMz6Srns+/ObrOgeu2EznoDCNBc2RAgwFs0HGTITQyBVf3Pap7IkVIlt
         Eu9Y0xtPUMwMZ+D390Iw5qll9fwODeoxXWN1M9Ma52SZg9QL3g+bFXFw2U2BTSREkD07
         SoSkELbg6gA7m+IsEhLqQz/N5uHaS/OT4WVhHcxnvCWmiiTb1p8MBLXKg+1iBxNFCVm+
         64IMYH3tpCJOvXtwepIV/OztjML4e3VLXnoXNji/14fZCf9o5+EUxQjdkYaGlSWPs09l
         CYfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700755492; x=1701360292;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=BX+uMKMKffnBqLzU4kZQxO55bPQEday30GkLDYF4iAg=;
        b=PB2ypDy5Yl8o2udAov3Ljjvmr30yIPS469OEvcH8HIATpauGnu8SN+ttMm1pFjCUxb
         8fnYBuS/xPWVSkWfJ+4Vit2of4VQWtf3bBX9mjFoHQWJYgGJvc7Y8M4okcC/3akU1SK+
         qnRzlDoVCFM71QkFcYv+CwP1XCrgU9F9jsGbChKqgyJ07VKmb2FcKHltOaEL0OnVghJJ
         mk44csIuOnqvy7D+4VHTc0R/oQpsX5sv5TE5z7DU8AZLQFxrFZbuuK/luufjZnQNfBOg
         99N0k7ptr82SehrLWxQV9/Wlc2zmMA8bP8HAWg6jTtIXsOc4kONCnbHDYwphwN5WH8NS
         +fsg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwS5oU/4J+uAXRFXhjQwkzYK1ZwGGN/8I6xyTSR7yglL7UHBQ6U
	aF3Lb94M2q6rUQQBDaKm6CU=
X-Google-Smtp-Source: AGHT+IFAcHsEoVW+OudvGV8QRE04ajJK9Ik3O7RRpMTEQx8Tk9RclrRx7gfkY8Ag3FHtcKCje33Dvw==
X-Received: by 2002:a92:d6d2:0:b0:35c:13e6:963 with SMTP id z18-20020a92d6d2000000b0035c13e60963mr2725049ilp.8.1700755492043;
        Thu, 23 Nov 2023 08:04:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c241:0:b0:351:33ac:94ce with SMTP id k1-20020a92c241000000b0035133ac94cels387982ilo.2.-pod-prod-00-us;
 Thu, 23 Nov 2023 08:04:51 -0800 (PST)
X-Received: by 2002:a92:6904:0:b0:35c:1157:9727 with SMTP id e4-20020a926904000000b0035c11579727mr2856714ilc.8.1700755491319;
        Thu, 23 Nov 2023 08:04:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700755491; cv=none;
        d=google.com; s=arc-20160816;
        b=oBfn5X4iWGaaAYepZPQnBl9vREelOAUu70mqCZvAli/MjjJx6/MBi17DvoY8Uk7zwt
         PZXPXrudafNPdpZR1TGQKboNIlZtOXqL2nK5A7R7JU8ZIHAnNSg36Fv/ZIrpYZz1IsLa
         LOtqiVhqs2bdxojv4KtH2VJ8qsIC0A8oGTWmguSAeKcW6NYwSWYwydf+wMPMr6mSa4gz
         WtuqyTEuj9n1AYowoUQlotkOwyF2JDRCRTKQHgZsn6CoX3HZ/W1kUuwNgHzGH9GHXf9J
         sxnHj4TIj0NBQTVALkDm8KHKCHnU9qOrap2fAtYwL3/wMnu5gz92yLkubmH8r2p74h5R
         IkAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=5yQnyP3lCf9W9/RzEaMbYWk0BN0vqCDasa+jrY8TA+c=;
        fh=sY3wElV5VHyiE/pHU4Rbii9LrO/Ppek15KCMEaKn7XA=;
        b=0KVkTwpo2A6/aBAKBRhMfTLnjp7G8gpVtAKq5QBDSuMBHvEuHX9h/8rn7LAXTUD9Ln
         axxeahdLNRS+P872hlJ/QtAwJyZqwLe9QOJo63bmBsOQEuSBaDQ/mTuVqg715R5mA+8P
         QE2QGH0N3I0gpnS2shSBgVpgtmX1XeIufHZh/vEzx/frXicVkBQkDEjOA67iy/S82pus
         hdqv9ojmvb7a9ObDwhMvcEJM/nOkaMYYY4RG4L3Z1c3k5XjPyLXgbrwOboQEaUgD/rp5
         GnAxxyyI5mJdpa75vYDn4LMCIzd4DF/r0yMoO/XDNfiMia2TccYpJGydEMS7pS59CiF0
         +6CA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ihQKFzf9;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f2e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qv1-xf2e.google.com (mail-qv1-xf2e.google.com. [2607:f8b0:4864:20::f2e])
        by gmr-mx.google.com with ESMTPS id o8-20020a92c688000000b0035aeaed6368si128279ilg.0.2023.11.23.08.04.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Nov 2023 08:04:51 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f2e as permitted sender) client-ip=2607:f8b0:4864:20::f2e;
Received: by mail-qv1-xf2e.google.com with SMTP id 6a1803df08f44-677fba00a49so8250336d6.1
        for <kasan-dev@googlegroups.com>; Thu, 23 Nov 2023 08:04:51 -0800 (PST)
X-Received: by 2002:a0c:ef42:0:b0:67a:bde:8898 with SMTP id
 t2-20020a0cef42000000b0067a0bde8898mr1865573qvs.5.1700755490737; Thu, 23 Nov
 2023 08:04:50 -0800 (PST)
MIME-Version: 1.0
References: <202311231356.1e1fb71f-oliver.sang@intel.com>
In-Reply-To: <202311231356.1e1fb71f-oliver.sang@intel.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 23 Nov 2023 17:04:39 +0100
Message-ID: <CA+fCnZd2JKZP43UJLciKOx2pRVwWDEUJZ0ik_BYC5atnwUGSfg@mail.gmail.com>
Subject: Re: [linux-next:master] [kasan] 0e8b630f30: BUG_kmem_cache_node(Tainted:G_T):Poison_overwritten
To: kernel test robot <oliver.sang@intel.com>
Cc: Andrey Konovalov <andreyknvl@google.com>, oe-lkp@lists.linux.dev, lkp@intel.com, 
	Linux Memory Management List <linux-mm@kvack.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Oscar Salvador <osalvador@suse.de>, Vlastimil Babka <vbabka@suse.cz>, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ihQKFzf9;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f2e
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

On Thu, Nov 23, 2023 at 7:19=E2=80=AFAM kernel test robot <oliver.sang@inte=
l.com> wrote:
>
> kernel test robot noticed "BUG_kmem_cache_node(Tainted:G_T):Poison_overwr=
itten" on:
>
> commit: 0e8b630f3053f0ff84b7c3ab8ff98a7393863824 ("kasan: use stack_depot=
_put for Generic mode")
> https://git.kernel.org/cgit/linux/kernel/git/next/linux-next.git master
>
> [test failed on linux-next/master 07b677953b9dca02928be323e2db853511305fa=
9]
>
> in testcase: boot
>
> compiler: clang-16
> test machine: qemu-system-x86_64 -enable-kvm -cpu SandyBridge -smp 2 -m 1=
6G
>
> (please refer to attached dmesg/kmsg for entire log/backtrace)
>
>
> +--------------------------------------------------------------+---------=
---+------------+
> |                                                              | 882f84db=
75 | 0e8b630f30 |
> +--------------------------------------------------------------+---------=
---+------------+
> | BUG_kmem_cache_node(Tainted:G_T):Poison_overwritten          | 0       =
   | 55         |
> | BUG_kmem_cache_node(Tainted:G_B_T):Poison_overwritten        | 0       =
   | 55         |
> +--------------------------------------------------------------+---------=
---+------------+

This should be fixed by "slub, kasan: improve interaction of KASAN and
slub_debug poisoning" and the most recent version of "kasan: Improve
free meta storage in Generic KASAN".

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZd2JKZP43UJLciKOx2pRVwWDEUJZ0ik_BYC5atnwUGSfg%40mail.gmai=
l.com.

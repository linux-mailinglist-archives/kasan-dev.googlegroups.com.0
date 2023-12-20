Return-Path: <kasan-dev+bncBDW2JDUY5AORB47YRWWAMGQEB5FIRYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id DE61981AB30
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 00:44:52 +0100 (CET)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-35fc2dfa75fsf28565ab.1
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Dec 2023 15:44:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703115891; cv=pass;
        d=google.com; s=arc-20160816;
        b=S4LkbMVWuml5R+2dDW69LMWMFpV5RRhHSK/ui68FQPBA1GiNg6kqSOKYv7zEdQWSeX
         E0QxlzqYk6fBsUDzxfQe79q/8lwnOtBexy4NccnYH0dz10ILxaunuF92JCsRnGtpeAdr
         1AP44nKCSPQy9XjouFyVd7gbvc+yorE65Z7HFF9+BECDeYzNRISHjKpkL92/H7j0ppk3
         3w8+rJK5gUk3NRiOSaX1rj50POGNmEGOozkCAxqk5gDln1nq+D4sgfgVH1XEXKobJ1jR
         Ca+rH2JkbZTc43OpXNY+qUdVPixkrWRtWd4ksqoRzDYrslNX+pBMviBxkl2eesUSZpmf
         Av4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=KUm3y82Oe9PcOfD8DLwroZdsOke7H0yr5iQbonlBNgI=;
        fh=mGRWHM9mAFtFUvHFzLTD+JuZeg3vpXmrMrpkkbhYbTs=;
        b=tNOq/IS84f0VlK5G/0KA0QAjJXbUmbHsaEgQtU+d6jin6ZxRIcOiTFkhj0anUYgu8B
         rN8OM+p1SnRM+eVdCuQlOzbJfLXx1/gLS2fVMVP6+L8MQenyBcRs7ChXcjYhzlYVgw9t
         LRVlOjRkWTxP3BsKzmP9n7xjnG5rwKDVhUdUhstPCqS/rCOuoxRJbuoQBLb/SNYeuuE/
         zDeQYvTvhqFuzQcNgMTAS+CbBnndiSjpYzmN0rtWQf3i3AaAi40oAbhDmEFXQxh6E6D4
         iG9GTcKvDImr1p+UzGqDxrDh0agx8aVkngoOmv9sFt2hJieJb70oyUUm3ZNsBWQ+9q9J
         +tIA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="LYt8+xB/";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2001:4860:4864:20::2f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703115891; x=1703720691; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=KUm3y82Oe9PcOfD8DLwroZdsOke7H0yr5iQbonlBNgI=;
        b=lS0KB/jiNWWLypPDHDgZ9QiGCNwlaAA75rk8ANL/mk9SnGyY030NXmLgFwBI/RX9Qu
         24ZaKSGJLbOVr/wyWnUWGMjFHGAP4l/Ipkr0F6SFVx5y35UsGR5T930ZLEN0ub0QTImf
         0MbijshU03SwXgkL7rCKo/gu+BhBZYmhn1D43PV8jWM14my5gTK3RC8W2u4xfzMb7lqS
         WVvFhl+JWUUy2uHQCsMC1UCmPbnmpYRzgGkTz4BJSzGvcKsZL4zP8nhiK62/2wMtSc2e
         TqYn7l4c9qweRjvMwVZE/macCGsVjZRVI8zqF3BdaGDy5rSXUEUrenAG1d2USB6tCopM
         fkjw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1703115891; x=1703720691; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=KUm3y82Oe9PcOfD8DLwroZdsOke7H0yr5iQbonlBNgI=;
        b=ndDnFyfY3C15/qFfhEomK4di3MYhgHw/0EwE96sMON/st9WD1cFcvdo1lEeLDJri9H
         iN+8iVxhcZV5T/0oHIOF4M3FgFAPYzzGfxY74NXLMsbP/6L4IU7+IO09VEbdXTHxmPYC
         +HqjYQl526Wlnt5vZorYgFKaTr/pe0202mOQysOWg+VTzBvlcEBj83HTyCJojNxvaIfW
         7vMFMIRoKy0Dpg8V0oDtyqMlyvdKHArB2rUm2smfx42wxbsV/Jq/HGmmAfg5EEjNXwgI
         0+JiWxFmbu8zpV09KzYPnaT6eEq/FdipWtvE0/M/pKVRm72v8Lz8qSHIP/+HRBp9otau
         vggg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703115891; x=1703720691;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=KUm3y82Oe9PcOfD8DLwroZdsOke7H0yr5iQbonlBNgI=;
        b=MCoZ3RsodCbaFeaf8HXJjQK7LoUxq/KPQSa8OkGaLa/ZAXVeL4l8flXY1sZrXCEzkF
         jUaDmifkeju7W9TVVccWy2dAbNpLY2YD+uP+5Cwi8AzdLfnSd9QfazAcAqbbWjesfY00
         Dj6KNFSCBtUoL3zj1x3/EI7QcY3ldpSP5ncjZFVNGjeCM5C8XaYXor2pK4t8iqYS1yLG
         6GhRXOYPmei9CTiZiXsA3TFBazaTDvyyNuLqg9nQtQSG0DiEzuiC7XRzF8MtinXzF6v8
         itPWuZxEERj4PpvkherhzRBmj+ap/SMHE+kTtOAZsXpU1E/zYuASjKvZJRq20gKQIbrC
         Ue0A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxeitYfGFitW5m6puI49m+6rGsYB3DNvGAfqOPoEI+gyd7xVJhG
	Uot7dNGCWr08vEAe64iA6UU=
X-Google-Smtp-Source: AGHT+IH9fGnPFTuo3lSUK1yjjXbPmVZoClU5ceAjb61NaJ7BAhqdMmzgbGRdOMexz4DaHXbwChvmwQ==
X-Received: by 2002:a92:b706:0:b0:35f:8fd5:3883 with SMTP id k6-20020a92b706000000b0035f8fd53883mr67799ili.28.1703115891337;
        Wed, 20 Dec 2023 15:44:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:9113:b0:204:277c:d663 with SMTP id
 o19-20020a056870911300b00204277cd663ls250872oae.1.-pod-prod-02-us; Wed, 20
 Dec 2023 15:44:50 -0800 (PST)
X-Received: by 2002:a05:6871:8ab:b0:203:c50f:6fc2 with SMTP id r43-20020a05687108ab00b00203c50f6fc2mr608127oaq.42.1703115890638;
        Wed, 20 Dec 2023 15:44:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703115890; cv=none;
        d=google.com; s=arc-20160816;
        b=i9C5HaUzSJLJJJD2L7pM+w/hO2B3YePWR5Rh8Gg9A/dR4AMSuuR5tStkL05PKEoeD3
         F+ygnNEsxjRTmcMzi77CXpjs3GIkeaujr011Cn2eQwmldUoHdoQi0YECuBkCZP2I0laY
         DptPP2/juufx1yz6g88JJer6W4d10nK0ZEG6ftIgwnLXph/UQz+d7EYrmk1in9jQwRI+
         kKHQt5qxa+zfaANae/yDV3Es+MMXgr6PQFJKIbsmqY6gBxR9RBvJtRRl13x+MFNoPjEV
         04S8xQO0bRS+4FnQ2rKhOH2CrHzK8MW7sLB2EwB699UhiR2msIbfjrkYJVW5U3+PaPod
         R6cw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=BRiqn6qJxrITE4e2Ib4uvsrQtS1W15KSJpparCjQXiQ=;
        fh=mGRWHM9mAFtFUvHFzLTD+JuZeg3vpXmrMrpkkbhYbTs=;
        b=JWox8F/OYPCy2bOpG962KrW+1XiklnPIEhCP/Jkoh9sElzSaPdzgfpLMGDzMcTFLxj
         h+VqHaa2eoduZwTygVsAuqGPUEjQiZgw+nebLRcXAhUhcphTo6uti86eHc4cJXF/VhUR
         stWogDlvoElApTYk8hy+qS7dCUNkRsQSMM0sXT94ptfk/BPwDF6/gkc+ULzWwFzxD2N2
         Wc4MJho8kqJ9SEib3jb57lsi7Z5sSpQRyP3LrNHHZGxGUlgW5WsXRbyoGHl7yGzXxwut
         pDINsHtPk/GoA7BtPdpcDkTnXLNOA9EmzgRh8ByauRrsFHxSDF1bBNQKxdffCUCbKTTl
         yiTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="LYt8+xB/";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2001:4860:4864:20::2f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-oa1-x2f.google.com (mail-oa1-x2f.google.com. [2001:4860:4864:20::2f])
        by gmr-mx.google.com with ESMTPS id ws22-20020a056871ab1600b0020422fc069bsi129627oab.5.2023.12.20.15.44.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Dec 2023 15:44:50 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2001:4860:4864:20::2f as permitted sender) client-ip=2001:4860:4864:20::2f;
Received: by mail-oa1-x2f.google.com with SMTP id 586e51a60fabf-203ae9903a6so102982fac.0
        for <kasan-dev@googlegroups.com>; Wed, 20 Dec 2023 15:44:50 -0800 (PST)
X-Received: by 2002:a05:6871:288:b0:204:1ae1:e538 with SMTP id
 i8-20020a056871028800b002041ae1e538mr546549oae.6.1703115890207; Wed, 20 Dec
 2023 15:44:50 -0800 (PST)
MIME-Version: 1.0
References: <20231204-slub-cleanup-hooks-v1-0-88b65f7cd9d5@suse.cz>
 <20231204-slub-cleanup-hooks-v1-4-88b65f7cd9d5@suse.cz> <44421a37-4343-46d0-9e5c-17c2cd038cf2@linux.dev>
 <79e29576-12a2-a423-92f3-d8a7bcd2f0ce@suse.cz> <fdd11528-b0f8-48af-8141-15c4b1b01c65@linux.dev>
 <CANpmjNO1_LxE9w4m_Wa5xxc1R87LhnJSZ3DV59ia3-SdQUmtpw@mail.gmail.com>
 <CA+fCnZfhqQ+n0SsZU0RKEov3CkwTNJXM7JTMxtkrODmbJPskDQ@mail.gmail.com> <fec2561d-42fb-dd47-6e8f-3b55aaf39d85@suse.cz>
In-Reply-To: <fec2561d-42fb-dd47-6e8f-3b55aaf39d85@suse.cz>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 21 Dec 2023 00:44:39 +0100
Message-ID: <CA+fCnZecUGRdqwfebu9C+hBN3_mW_VNhjm4FUXOo9Xak58NKdQ@mail.gmail.com>
Subject: Re: [PATCH 4/4] mm/slub: free KFENCE objects in slab_free_hook()
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Marco Elver <elver@google.com>, Chengming Zhou <chengming.zhou@linux.dev>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="LYt8+xB/";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2001:4860:4864:20::2f
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

On Tue, Dec 12, 2023 at 12:42=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> w=
rote:
>
> On 12/11/23 23:11, Andrey Konovalov wrote:
> > On Wed, Dec 6, 2023 at 3:45=E2=80=AFPM Marco Elver <elver@google.com> w=
rote:
> >>
> >> The is_kfence_address() implementation tolerates tagged addresses,
> >> i.e. if it receives a tagged non-kfence address, it will never return
> >> true.
>
> So just to be sure, it can't happen that a genuine kfence address would t=
hen
> become KASAN tagged and handed out, and thus when tested by
> is_kfence_address() it would be a false negative?

No, this should not happen. KFENCE objects never get tags assigned to them.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZecUGRdqwfebu9C%2BhBN3_mW_VNhjm4FUXOo9Xak58NKdQ%40mail.gm=
ail.com.

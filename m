Return-Path: <kasan-dev+bncBCCMH5WKTMGRBEWNSXGQMGQEC2LWISA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id iGeGEZVmpWmx+wUAu9opvQ
	(envelope-from <kasan-dev+bncBCCMH5WKTMGRBEWNSXGQMGQEC2LWISA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Mon, 02 Mar 2026 11:29:41 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb13f.google.com (mail-yx1-xb13f.google.com [IPv6:2607:f8b0:4864:20::b13f])
	by mail.lfdr.de (Postfix) with ESMTPS id DFFB11D682D
	for <lists+kasan-dev@lfdr.de>; Mon, 02 Mar 2026 11:29:40 +0100 (CET)
Received: by mail-yx1-xb13f.google.com with SMTP id 956f58d0204a3-644548b1dcfsf5739731d50.3
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Mar 2026 02:29:40 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1772447379; cv=pass;
        d=google.com; s=arc-20240605;
        b=c6TmZIa61tODlTYVBLgv758GE2bI+hUp0ANXyZa9nKIA/RJYHEhW5uhty5VfEtjUq1
         z31DLkwX64kV6wQtuEbIyyGxoB2R5T9HJS6djEj2d5DeQOz9uDGzLIBRemlXyOrFOGg9
         dsmh5kYn5jANIY5zmO3Dn9ifMbaH0AdDYFmY8u3onzA8KNr8leZUv+Fm/lciHgl/4Grp
         YPoyAiNVOSKm80SbaZPUOWR5DbOmG5Mm8u6ZV77oct38MjEYA1Ah+c77YJIKbZ4A9ohz
         sADXk5X9dww38+jR0++cEERVdcECUjKhhsK1sP+pFet8DR62ZWwxYRMvF2r4/kBQYGL/
         9ZCg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=StkRwAwX+ZhuaLyKUV8X/BPxyr6BFchZF1Db5KdvCYw=;
        fh=ALj+Kxdb4pEBjRt9WLPfnfyB4++stn8szsOFIBghZ2I=;
        b=N9qvix8Mj/oMRx2aw/Iz13SRpQJK02JMD2KbI6Tq7vUCE7dHkhQGhQ+8ppXGFsJiry
         lAA5cOkE8G0dELHpCIZVW/y9YM1jP4ZtBNDm/lPKuDyTuzBnNyqTqcRAruJ78XtaJl/x
         djeIq02TTv+H+ICYJ9laEPwgZ8jwn8kcxn9rQFITGzxL8+wn3vZ7dsukN0sc3DkxkcEf
         8LCHSy1iH/jYRHkRTJc65vyUy9UiNLNz/e4OisqjUvDdcfo6XTtpjA/rK0cvVNx+Wi5s
         pyg6O1Quhzu9rNsTzuYVsii+9i83rCt28jLOa7cQI2n7Dm35eDtUEGEmzVVWLCF4hSpf
         VKTA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="daje9Dw/";
       arc=pass (i=1);
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::729 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772447379; x=1773052179; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=StkRwAwX+ZhuaLyKUV8X/BPxyr6BFchZF1Db5KdvCYw=;
        b=f7qqjmHzmGAOLKqQW1uSBzqtIg3+ZUlNUdvPaLVEJTBh4jwDEh/yb3d7bSaVHXg1OQ
         ITSqXwOxB/Zx9hXgkoPyV7+YxVIeeDYEsfhoQWJgXpN5NNOLVWSRHUzSLlZhZqjMok1U
         zXS1cgus5SaGQ3R+eCs5/iJL0fSkLZSMQ1Yxr7zWCmb2xUKVZgeZo2JRMIEeAvKHI09F
         IPbtxWgpGIq03Vk+CVk2YOAVEuUxTzcmgeKHYuFeUlq6Hr5ogHGx/ys9p6mavjjGDus3
         3S2dZDCxBiawN+H3pVCSDVPt9dWH6I0eNTOfxrUnzIXr4vV8h1E4p6ksaw2Cdu0VtRMx
         MEfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772447379; x=1773052179;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=StkRwAwX+ZhuaLyKUV8X/BPxyr6BFchZF1Db5KdvCYw=;
        b=raZA7O3LDdqnmQ8cvmf1djATTW6oFeqnNciZPT2rzyEzRjTnVzHh5NdHuA2G0bu8hB
         YR3GVm6ORkUsqcz+HPWP6Dap4M2rj2iz+j7SOaLuOmSlQkPdaY36TY5/XIMbQuM2Q/HH
         DzAUCgrJ39peJQF5nKKEbe9hTBuFnvglkXu0MQvswAMPNJjd0ykXKM2trdwgXqA8Uoxj
         +mO9GitYOWeMdxdgReTwZdwBdtwoJ9jSFaT9ygcWu5HTiNX+JYKAZ5c1OYQa0VFhYj2X
         WzcLiC1v2UdkWIdtYO6a9hZwiISl4JrthJ/wzQPsNz7t9+xaZ6MlcbABak1THVsjUU1j
         tyKw==
X-Forwarded-Encrypted: i=3; AJvYcCXAFKKK3ZlFqHKgItn8pGSvWfHdjcWahR2AoNDSMqHUOTcs3PgeU6n9KazzI/x4ENZby7DcfA==@lfdr.de
X-Gm-Message-State: AOJu0YxmmjFEb7YeGwEby06EbjYrG6nCUYIzha9cJf9d4EepRC5Ip2dG
	xPD31UtqH6Rdm76Kw8a1quGivv8G8oS5QUDeEmtQVwu4PZoK/aXcMWbk
X-Received: by 2002:a05:690e:4105:b0:64a:f285:e673 with SMTP id 956f58d0204a3-64cc220ffdemr10685252d50.52.1772447378954;
        Mon, 02 Mar 2026 02:29:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+F52fckIdQTccVEUNQ/IYBlyAhAJZfgNfIKCwy4lhAi+Q=="
Received: by 2002:a05:690e:24dc:b0:64c:9c47:5ce0 with SMTP id
 956f58d0204a3-64caaaf9083ls3730054d50.1.-pod-prod-01-us; Mon, 02 Mar 2026
 02:29:38 -0800 (PST)
X-Received: by 2002:a05:6122:428a:b0:56a:7f37:d18f with SMTP id 71dfb90a1353d-56aa0a375aemr4701458e0c.3.1772447378111;
        Mon, 02 Mar 2026 02:29:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772447378; cv=pass;
        d=google.com; s=arc-20240605;
        b=A1ZmLnd/6kiWbuVboUieQ4z7dGKlwjWYjPGfQE6vBtgzje9Kzb3IVQBesutAYVvBo6
         T8iAN7Zkqw1LHIbompQCcPa8J8krqNmB6ITwpd7K0olZUUw4orWj6DiKTlwvDIAGykvb
         +MwCX+8h402maygb+S+T5amLwnzK+UgNWZjBowetflicvqAYaBxg2xZ5ZcLMENAabfkY
         z+RI7G5ffVUJ3CRVd4mZCtBMXM6npkSekeA1AoeD1eoXoXfJI4KFMA86uZ55/X9kP2xu
         2I02R5AedmxzUsRAifaxDY6HN1dExvHD4FWK7NwZ/uFAYmyWtJtjIyrw9NX8GVcQ+0Tv
         EQ0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=h/njpkbtZVt3Kl+KjZ5piSQhFiqZBY8slUODGXpsT5Y=;
        fh=oPG2Lt+yCLKM3JySyb0Kf3rp4X1v3Qk0hIOiPrnnjyg=;
        b=cmjGlew3UIKAhUMgpCgJO7Wm5qPqG8ovN0DLK8yTN4S7LcH2uVR1GY6G4lkNbuvOyA
         /bGVxsyKr9XirAD8pPuS4F7DG1IkTyzcYwsGNDETjwHHdBEU7b3O+ocPTpTdOy/5P7Dp
         KLletTYR3HWzf/3byTWDjWQH0y8HaYLzoaYXruwakjqA/zl/KCUs4AYJTvnFnPmKJRyx
         CQbK7yYoIvO4MjGPbp7i7FAHSCVX3MgBJxMT5Zs/0fNGwRDfLv3Nw17aa5N+Wk6b3A7I
         w4GvnOxYHq8z91ZSZjGuB75OvZi8ZVK4haXWho99krt0As1Y8dG2wu68fnHkC5rGrU17
         BY9g==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="daje9Dw/";
       arc=pass (i=1);
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::729 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x729.google.com (mail-qk1-x729.google.com. [2607:f8b0:4864:20::729])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-56a921543e9si428942e0c.6.2026.03.02.02.29.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Mar 2026 02:29:38 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::729 as permitted sender) client-ip=2607:f8b0:4864:20::729;
Received: by mail-qk1-x729.google.com with SMTP id af79cd13be357-8cb3fb47559so516602085a.1
        for <kasan-dev@googlegroups.com>; Mon, 02 Mar 2026 02:29:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772447377; cv=none;
        d=google.com; s=arc-20240605;
        b=WcoFQPFdZQVRj+cwCxyRNnKN3deqNDRkOtqVDOKp7l9RNSLGXhw9Mzag9kuFzcjxag
         w9L3H1dx/AYvyp8E9E4eTbGTLpeVpN3PwtMRh0eGVIGNbDiOo9DZPzP18+HFy0twgdYl
         K2JmWN+S0n7Cv5BpAjvARE882H4xLWSz5FD15Nek8eM/b629rfc1mtKetFbOVdnO0Rqt
         gF7Abz+bc3/odGy83KspDAYZFiTEGAPpJlODhnhOgtB8tPjIdQTVEgfzAAj+nHeFYVon
         EWr+tWMyu/KDVwCkV59DsGMxhaCRIHDzO8szZ83Gn52DJqruW2WYTr4gwWwQDY7Ci0V5
         EOJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=h/njpkbtZVt3Kl+KjZ5piSQhFiqZBY8slUODGXpsT5Y=;
        fh=oPG2Lt+yCLKM3JySyb0Kf3rp4X1v3Qk0hIOiPrnnjyg=;
        b=iXJqgXPJe6lT4QNNdbtqR1qqwVv5eLELEMgc3K5UC0y5XRe14PH6nj4WLBH9J3jn6v
         F0IVSlXaAfFqsXgy+zgKRvxrIVeXNuZxC2M9WuvnEZhs397dNlLz0QvTCtYoBpdQD4TL
         vkMC0K7NXRo5Vk/1Qwy0XIDJWJ1snYa5dhzTRgJOaRMqt0OWF5Azase9MjFPiD4HnfV5
         VAV7LA8H4v8nYsHu6JrGpEfvvpRefxPF7+zFcaBoEOWwIhFjI6stexQfM89Ft1bx1aBa
         ZOPkFZahLxl6XVw0j6NPljhSLJas9ZfkbxIMf9ab7wy5EzTJQY3/DHLL4lQ64qVH80+1
         dubg==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Gm-Gg: ATEYQzxPhg264TQlasjhs8UeEkkn3TkefiiZLMcx2N4+mijOHu3B/vpUShR3qXA7prm
	uc5xsOutONr8naCfhICMdudv/CaE9IzdFC+32YPnR8so+S7r8xXQWrPRLcwBEAWTmWXn3qZ8Ubk
	/62JJB2/wc+d4gVbBG0McQ8XZMN/5mVmCa7T7kKA6OxAbWGlr8oyawtJ15pq61lfLS8W38nPyYe
	JJTeGduVt84jiPgJjSOrMt3yq/M0SJxAk5dnU16UwbLdtM6FwZPN0ywH0fxViM95rLd2iWY2hYI
	2P+tGsTOVYVpUz21jd5gpQCMaKoW+NEgfKLjFA==
X-Received: by 2002:a05:620a:450e:b0:8c6:b14e:6569 with SMTP id
 af79cd13be357-8cbc8e3099bmr1545558085a.79.1772447377161; Mon, 02 Mar 2026
 02:29:37 -0800 (PST)
MIME-Version: 1.0
References: <2f9135c7866c6e0d06e960993b8a5674a9ebc7ec.1771938394.git.ritesh.list@gmail.com>
In-Reply-To: <2f9135c7866c6e0d06e960993b8a5674a9ebc7ec.1771938394.git.ritesh.list@gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 2 Mar 2026 11:29:00 +0100
X-Gm-Features: AaiRm53DRbj7sPLIop0CBXc5s2h5N9WBGDepItjpg99dPeJvb65reF4OaqPzMX8
Message-ID: <CAG_fn=U5weotUtW+TKmX_WRvRSaH+UiqdeDx-4foxVKK_kLNYw@mail.gmail.com>
Subject: Re: [PATCH v2] mm/kasan: Fix double free for kasan pXds
To: "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	linuxppc-dev@lists.ozlabs.org, stable@vger.kernel.org, 
	Venkat Rao Bagalkote <venkat88@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="daje9Dw/";       arc=pass
 (i=1);       spf=pass (google.com: domain of glider@google.com designates
 2607:f8b0:4864:20::729 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBCCMH5WKTMGRBEWNSXGQMGQEC2LWISA];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	RCVD_COUNT_THREE(0.00)[4];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_TO(0.00)[gmail.com];
	TO_DN_SOME(0.00)[];
	FREEMAIL_CC(0.00)[googlegroups.com,kvack.org,gmail.com,google.com,arm.com,lists.ozlabs.org,vger.kernel.org,linux.ibm.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	RCPT_COUNT_SEVEN(0.00)[10];
	NEURAL_HAM(-0.00)[-0.994];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	HAS_REPLYTO(0.00)[glider@google.com];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail.gmail.com:mid,mail-yx1-xb13f.google.com:helo,mail-yx1-xb13f.google.com:rdns]
X-Rspamd-Queue-Id: DFFB11D682D
X-Rspamd-Action: no action

On Tue, Feb 24, 2026 at 2:23=E2=80=AFPM Ritesh Harjani (IBM)
<ritesh.list@gmail.com> wrote:
>
> kasan_free_pxd() assumes the page table is always struct page aligned.
> But that's not always the case for all architectures. E.g. In case of
> powerpc with 64K pagesize, PUD table (of size 4096) comes from slab
> cache named pgtable-2^9. Hence instead of page_to_virt(pxd_page()) let's
> just directly pass the start of the pxd table which is passed as the 1st
> argument.
>
> This fixes the below double free kasan issue seen with PMEM:
>
> radix-mmu: Mapped 0x0000047d10000000-0x0000047f90000000 with 2.00 MiB pag=
es
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> BUG: KASAN: double-free in kasan_remove_zero_shadow+0x9c4/0xa20
> Free of addr c0000003c38e0000 by task ndctl/2164
>
> CPU: 34 UID: 0 PID: 2164 Comm: ndctl Not tainted 6.19.0-rc1-00048-gea1013=
c15392 #157 VOLUNTARY
> Hardware name: IBM,9080-HEX POWER10 (architected) 0x800200 0xf000006 of:I=
BM,FW1060.00 (NH1060_012) hv:phyp pSeries
> Call Trace:
>  dump_stack_lvl+0x88/0xc4 (unreliable)
>  print_report+0x214/0x63c
>  kasan_report_invalid_free+0xe4/0x110
>  check_slab_allocation+0x100/0x150
>  kmem_cache_free+0x128/0x6e0
>  kasan_remove_zero_shadow+0x9c4/0xa20
>  memunmap_pages+0x2b8/0x5c0
>  devm_action_release+0x54/0x70
>  release_nodes+0xc8/0x1a0
>  devres_release_all+0xe0/0x140
>  device_unbind_cleanup+0x30/0x120
>  device_release_driver_internal+0x3e4/0x450
>  unbind_store+0xfc/0x110
>  drv_attr_store+0x78/0xb0
>  sysfs_kf_write+0x114/0x140
>  kernfs_fop_write_iter+0x264/0x3f0
>  vfs_write+0x3bc/0x7d0
>  ksys_write+0xa4/0x190
>  system_call_exception+0x190/0x480
>  system_call_vectored_common+0x15c/0x2ec
> ---- interrupt: 3000 at 0x7fff93b3d3f4
> NIP:  00007fff93b3d3f4 LR: 00007fff93b3d3f4 CTR: 0000000000000000
> REGS: c0000003f1b07e80 TRAP: 3000   Not tainted  (6.19.0-rc1-00048-gea101=
3c15392)
> MSR:  800000000280f033 <SF,VEC,VSX,EE,PR,FP,ME,IR,DR,RI,LE>  CR: 48888208=
  XER: 00000000
> <...>
> NIP [00007fff93b3d3f4] 0x7fff93b3d3f4
> LR [00007fff93b3d3f4] 0x7fff93b3d3f4
> ---- interrupt: 3000
>
>  The buggy address belongs to the object at c0000003c38e0000
>   which belongs to the cache pgtable-2^9 of size 4096
>  The buggy address is located 0 bytes inside of
>   4096-byte region [c0000003c38e0000, c0000003c38e1000)
>
>  The buggy address belongs to the physical page:
>  page: refcount:0 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x3c3=
8c
>  head: order:2 mapcount:0 entire_mapcount:0 nr_pages_mapped:0 pincount:0
>  memcg:c0000003bfd63e01
>  flags: 0x63ffff800000040(head|node=3D6|zone=3D0|lastcpupid=3D0x7ffff)
>  page_type: f5(slab)
>  raw: 063ffff800000040 c000000140058980 5deadbeef0000122 0000000000000000
>  raw: 0000000000000000 0000000080200020 00000000f5000000 c0000003bfd63e01
>  head: 063ffff800000040 c000000140058980 5deadbeef0000122 000000000000000=
0
>  head: 0000000000000000 0000000080200020 00000000f5000000 c0000003bfd63e0=
1
>  head: 063ffff800000002 c00c000000f0e301 00000000ffffffff 00000000fffffff=
f
>  head: ffffffffffffffff 0000000000000000 00000000ffffffff 000000000000000=
4
>  page dumped because: kasan: bad access detected
>
> [  138.953636] [   T2164] Memory state around the buggy address:
> [  138.953643] [   T2164]  c0000003c38dff00: fc fc fc fc fc fc fc fc fc f=
c fc fc fc fc fc fc
> [  138.953652] [   T2164]  c0000003c38dff80: fc fc fc fc fc fc fc fc fc f=
c fc fc fc fc fc fc
> [  138.953661] [   T2164] >c0000003c38e0000: fc fc fc fc fc fc fc fc fc f=
c fc fc fc fc fc fc
> [  138.953669] [   T2164]                    ^
> [  138.953675] [   T2164]  c0000003c38e0080: fc fc fc fc fc fc fc fc fc f=
c fc fc fc fc fc fc
> [  138.953684] [   T2164]  c0000003c38e0100: fc fc fc fc fc fc fc fc fc f=
c fc fc fc fc fc fc
> [  138.953692] [   T2164] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D
> [  138.953701] [   T2164] Disabling lock debugging due to kernel taint
>
> Fixes: 0207df4fa1a8 ("kernel/memremap, kasan: make ZONE_DEVICE with work =
with KASAN")
> Cc: stable@vger.kernel.org
> Reported-by: Venkat Rao Bagalkote <venkat88@linux.ibm.com>
> Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DU5weotUtW%2BTKmX_WRvRSaH%2BUiqdeDx-4foxVKK_kLNYw%40mail.gmail.com.

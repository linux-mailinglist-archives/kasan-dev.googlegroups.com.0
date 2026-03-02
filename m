Return-Path: <kasan-dev+bncBCCMH5WKTMGRBOW7S3GQMGQEMAINSNY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id SNVMNryvpWleEQAAu9opvQ
	(envelope-from <kasan-dev+bncBCCMH5WKTMGRBOW7S3GQMGQEMAINSNY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Mon, 02 Mar 2026 16:41:48 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113d.google.com (mail-yw1-x113d.google.com [IPv6:2607:f8b0:4864:20::113d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D4E91DC0A1
	for <lists+kasan-dev@lfdr.de>; Mon, 02 Mar 2026 16:41:48 +0100 (CET)
Received: by mail-yw1-x113d.google.com with SMTP id 00721157ae682-79885818011sf54494147b3.1
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Mar 2026 07:41:48 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1772466106; cv=pass;
        d=google.com; s=arc-20240605;
        b=L+HqDgL5adoz+oJyrYSzUHY0+EzchfGgTdcg8uQt7xaWzN3WQXoti2v4ATNuG/yV5r
         3ixhDh77owk3/2Y3GpHwY9E+ko783WBcCuKGa++oKFH9uoaXpIEa92BEEu/Plhx7H3yS
         Ym9C++FTg/Ace8qn+CwPB3JKkKJZdppODAWm4B9PgSl49JtVWGPcgtrWtH19rbOrgZi6
         5f1V7iFPHMQm+SlcXV8DK7gzSdaOVyKeZjpe0naYaR4kDzEtDnpQHiWhV6QRZX9DSSNA
         rtQ0Sr4SPNyPNbzhQ/K+9ku7IN3j17e+PdNV90KF8zPrZYpeasglTVj35nfUnUns0KIP
         yLGw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=87hH/rCN6SsrlPpXcBLnrNVD+r/Lvg3qfQNCj4SggCg=;
        fh=eYcI+ofMNpBVob5DExxtb3nO5R/JlSddvmfGAkhzZbI=;
        b=L97ajL6bWj0WxOuyv/NctyCqN0UM9y0wMWYvQlP6gcVNbFNku2eZNCuXZPelEod6h6
         QD4QRRh7EyJWgpoDh3W5UcD6yG9mmcpBZXEZy1FqEXFA5t3QjrHMpgSDPX4STkSCgagS
         Pi7TCbMqHq0i3XGGb0J/A0tzFf6glikwmk1cNpMoJ11wJDH8nuuxTcZH4zqlEzHmMKXg
         fg4RHzdxLuYIFtYRWWPeCQzQbX8aQ/VmJ+AacapsO/FpiHve1qecEhRWkwb2y1PpNUL6
         rvenkL7klF7fjWHGH00jTZ3Odf3V83YUi96wtAB+UKV91BrxbJshb7WFo9iLaorT+GzH
         HDfQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=3W7tnM9L;
       arc=pass (i=1);
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772466106; x=1773070906; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=87hH/rCN6SsrlPpXcBLnrNVD+r/Lvg3qfQNCj4SggCg=;
        b=uTMhLi/5o6R2/F8OAGdiSjMjQ/ijImShfLTJ0EYVzDJypfIxlQJqhIpL4N4rlhne9M
         srML+voJGkjlCt0acRS6zneoG6i7ZQ/cQDASNDD5t86LsZ0uC/QOpph/FiJPCBfrMhlZ
         ITqIDW3sdmw4F54HSAGnjhxCRPnmkZOr1NeNmYGElt2MJS+SWHCCZKuulL5vIm8U0Q4k
         ONLQycaqxntiZi7crI/KcE1tGpeQZr168CJIQZJWzBLlXEjNKxhb7JcTc9wcmDK788ja
         Fk2Tv341R8dCGh8166TsQVJtFDCo7g/d6muJOS1li17K1mUgRFSAW+FbulDXxXe9ooiC
         aOsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772466106; x=1773070906;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=87hH/rCN6SsrlPpXcBLnrNVD+r/Lvg3qfQNCj4SggCg=;
        b=gAnICL9SA7o3YofLOMb6g+Q6mBANq2k5oSmyPe9J5+SmN4FATTLARCWv/NXrLYP4NB
         ni0vb/yWO1kvy11oB8VbvXannnoSw1Ezt2ZA1NfHKUIpgzkrbFLpyn3V4VHoEHRMcAgy
         HHCsQ1yXMqY6N57g91I0mos6pIJE9ix70QSxFCKCRysN1LcfJ9+EYXP/l9ZSojX5jGi+
         lbKPtcJhtQNJSW14Rvy9Fl5DN4ezu1u+LZEP9vDtYx51+BuKywTpPhUaDmcxQriDwyiT
         3FlQzbhH85c0d++oQxXAGwVYnbc/qj9GHTI3vlDgVF59Ox9AXWSCeiYdNboJyYHCdFVy
         opqg==
X-Forwarded-Encrypted: i=3; AJvYcCW68d7m0Xl+PEPmaB/+jD17fNO9mFsdCTggNBJSda/XUOod2CwdZr+yufE7Rh9m0fJp3dXuBQ==@lfdr.de
X-Gm-Message-State: AOJu0YwqY6qxUnLNDheS2+N3FjoowfhKqmK6FVmK+Eqxbioza9gZZflV
	itdvcibV2exv0klvzmAODh/f7IBfPd/rzb3yxnTG18psbgvxg4ib2YdN
X-Received: by 2002:a53:ac9c:0:b0:649:b851:4eb with SMTP id 956f58d0204a3-64cc22100bdmr10569050d50.53.1772466106612;
        Mon, 02 Mar 2026 07:41:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+H280q294CPPCw4q5JoYoSDwsCKaqwx7ymBXRseikJDQw=="
Received: by 2002:a05:690e:1585:20b0:64c:c64e:90b7 with SMTP id
 956f58d0204a3-64cc64e90d9ls2233314d50.2.-pod-prod-01-us; Mon, 02 Mar 2026
 07:41:45 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCWurpOV4VKWv4SS71u0Li6Sw+jTeaBfWiQyL1bpGlQuB7mZfKRQ4uKBqkN8lUNCeeUN1IebGuAcNNg=@googlegroups.com
X-Received: by 2002:a05:6122:a0f:b0:566:963a:165e with SMTP id 71dfb90a1353d-56aa08cc5bfmr5519948e0c.0.1772466105436;
        Mon, 02 Mar 2026 07:41:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772466105; cv=pass;
        d=google.com; s=arc-20240605;
        b=erABpvEyoCDYEWq1rB61jHGgurHDOdVMj+MheuKrWpbLllxl+CWXOvUDVgvtq+CLDv
         9+/F9hO7q+vwA5NOmEC0coy7fSVlt1yJYz6cIWjyhvNATPRtlJjxxw5zGAavI7+6OSyL
         XlMVWMjNu0HONtuHe7Cq0MvnlDnGEmUx+hx2sKK6S7XzqmhirH933tyec1EfrgbGmMwS
         RGp+EZtXiES8eaMftPIHmfNEAY6xeHQiOkNa+kGK0uQBLINumpcgi+EZM844g0OZmOhO
         4N9unlpFXWdKi9Im6SEoSdTrhYBIIQJ8fk5Cqqq3e6648uqcvWWjsF3cXQL3YE7CNN/z
         9FrQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=AXg6Ypvqjq2PoxAf2Q1/vJlxrd14L9sIF+RlfxzIaKI=;
        fh=qzf3lSoq/zgUR8afnGKiIRqXiEfy0fT6SjPXA+ENbRk=;
        b=IutOsUF7eVMKQ12paYKqMblzLbrdmgbtDXkcIkukll4HnU51HueQXSxw0WJDT+rDlX
         W9zNlMJQ+zGDfea/d544ZDmH+9P2tUcBDqgH14JDdyopoMtPj8khCADYywgMq0WhWO30
         aGef6muknN/bwbc0z/iyVTCpAAAjq9HR57K6jZtRs83sgVwpcCGCwT2eiau0gcnW+kDV
         fFoL94m0+LRlWIpCZlBabAzHr1rKIgYKUcBLiy1pnnpCpkgMByvQrIHY3HLpM5blGV7+
         M4bnXmoGh7TSIB9OQLwWeSYYHxoVoNJMOVeA6wuIi3mXkvtlmW3Mmc3Oc9XTqrV0u173
         xhJw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=3W7tnM9L;
       arc=pass (i=1);
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2d.google.com (mail-qv1-xf2d.google.com. [2607:f8b0:4864:20::f2d])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-56a91b898f2si464117e0c.2.2026.03.02.07.41.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Mar 2026 07:41:45 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) client-ip=2607:f8b0:4864:20::f2d;
Received: by mail-qv1-xf2d.google.com with SMTP id 6a1803df08f44-899b95707afso63743656d6.3
        for <kasan-dev@googlegroups.com>; Mon, 02 Mar 2026 07:41:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772466105; cv=none;
        d=google.com; s=arc-20240605;
        b=UoMxdmqjg4qrfkl0G3X2czispSdlHPu7LRt62CxjhrhLbbWc+3FqeaMRzBB0YLURDI
         Kgi5pULXiiCGdyIEhBcNQOvsWKXfebeDGFOa5PWnjof33rj0iPceHQjubJpIP9aBOH8P
         G1/LByR8XP/SpgbzxxYl1JBZOKAengeZeAT2g3kUjLzH8z/wGzghWmX2TfynA29yCheW
         UJv5VkfRLoS1AOaIwhlYOprS8GZCZB9khholKDzN1YchZNLQTpWsVJp1zStY8/XMR/zQ
         dvwoFoZ7Ox8F5thw52q3HhPHveuf6PePky2hpCBMSrbesIe1wSR8wDmsv2JMLiloRZQL
         XqGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=AXg6Ypvqjq2PoxAf2Q1/vJlxrd14L9sIF+RlfxzIaKI=;
        fh=qzf3lSoq/zgUR8afnGKiIRqXiEfy0fT6SjPXA+ENbRk=;
        b=azfiF6rCLlVGIF4Y5y4sBDO9L3kptriplUfyrwxFBcVr8ZmEDzQ1Ttg5d4bYwxDHJB
         MX+Xf66dCXgij9Z0BDv4Mn8fv8SyLHrtKAqAItORFnPrH/DoaRZeq8EhcY8epsDiQ7Wu
         mfVCYiiVjyA0+cO6FK0vOONaDbPZ3d9ATqw900VIqgCQlIdQOcs34S6NTU8EUI9ODe6W
         pebmxkNEvo1ZEbSvH+kKdMn+GAzYkolCnBJ2a++9eRZLuxAXvSHtHtL0bcZEWEjATtkb
         Dw7q3RtdO85MYZ9xOR3/2uxxj/zrGxReyGM53dROVVtmTY4YMPh2L98zyKDfBow/aBpb
         hzsQ==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCWhrs6LiRomlblsam2gDPRHTkQ5ws4Hxi55sVJFKRNCxnPL+8Yo9rzTjVxF1hqa6OUafn8sQwJ0dBU=@googlegroups.com
X-Gm-Gg: ATEYQzxpx50mZCZc2FpbjJToRANv/SXDKmeA0p2wgiRCtFXDnRdsSkyE2WFNjdALtx6
	dy5MDW9+3rd6v6m4mVkwRwU2W1y5toV+/31LVRybMipvPGaup1PFlxNk615TjVZ5eQd4Y8itjrj
	OYDo3ymYLVw109kBnZYfryR6Ytyrx6r0FSWj/kpGBNi5wLmlkGPm3oXxVYEZm99Nsh1u7L9wMYx
	VbUSoO2pvWeiGx5rPMEMSvFK4+Z+RZdA49rvvPoiRz3EwqVhzX5YH1DFTuNDFFPG4j/xDUQRcBN
	5+ujTOmbKEFXJQZml1I1m88NCuDvsiK7Z69N9Q==
X-Received: by 2002:a05:6214:b61:b0:899:edac:29da with SMTP id
 6a1803df08f44-899edac2ea4mr92564036d6.9.1772466104463; Mon, 02 Mar 2026
 07:41:44 -0800 (PST)
MIME-Version: 1.0
References: <20260302-handle-kfence-protect-spurious-fault-v1-0-25c82c879d9c@iscas.ac.cn>
 <20260302-handle-kfence-protect-spurious-fault-v1-1-25c82c879d9c@iscas.ac.cn>
In-Reply-To: <20260302-handle-kfence-protect-spurious-fault-v1-1-25c82c879d9c@iscas.ac.cn>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 2 Mar 2026 16:41:05 +0100
X-Gm-Features: AaiRm519c31SJCJvVbfmwtY5C0BIz6yZb5Q3Hs1_ztYk30q3Q8m7aBM-_x2qO04
Message-ID: <CAG_fn=UQj+bdY2YojmfVf=qRQgCttD=PqE0h=vm4pAbtNRP-uw@mail.gmail.com>
Subject: Re: [PATCH 1/3] riscv: mm: Rename new_vmalloc into new_valid_map_cpus
To: Vivian Wang <wangruikang@iscas.ac.cn>
Cc: Paul Walmsley <pjw@kernel.org>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Alexandre Ghiti <alex@ghiti.fr>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, linux-riscv@lists.infradead.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	Palmer Dabbelt <palmer@rivosinc.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=3W7tnM9L;       arc=pass
 (i=1);       spf=pass (google.com: domain of glider@google.com designates
 2607:f8b0:4864:20::f2d as permitted sender) smtp.mailfrom=glider@google.com;
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
X-Rspamd-Queue-Id: 7D4E91DC0A1
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-2.21 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	TAGGED_FROM(0.00)[bncBCCMH5WKTMGRBOW7S3GQMGQEMAINSNY];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	MIME_TRACE(0.00)[0:+];
	RCVD_COUNT_THREE(0.00)[4];
	TO_DN_SOME(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	HAS_REPLYTO(0.00)[glider@google.com];
	NEURAL_HAM(-0.00)[-0.999];
	FROM_EQ_ENVFROM(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	RCPT_COUNT_SEVEN(0.00)[11];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail.gmail.com:mid,googlegroups.com:dkim,googlegroups.com:email,iscas.ac.cn:email]
X-Rspamd-Action: no action

On Mon, Mar 2, 2026 at 3:21=E2=80=AFAM Vivian Wang <wangruikang@iscas.ac.cn=
> wrote:
>
> In preparation of a future patch using this mechanism for non-vmalloc
> mappings, rename new_vmalloc into new_valid_map_cpus to avoid misleading
> readers.
>
> No functional change intended.
>
> Signed-off-by: Vivian Wang <wangruikang@iscas.ac.cn>
> ---
>  arch/riscv/include/asm/cacheflush.h |  6 +++---
>  arch/riscv/kernel/entry.S           | 38 ++++++++++++++++++-------------=
------
>  arch/riscv/mm/init.c                |  2 +-
>  3 files changed, 23 insertions(+), 23 deletions(-)
>
> diff --git a/arch/riscv/include/asm/cacheflush.h b/arch/riscv/include/asm=
/cacheflush.h
> index 0092513c3376..b6d1a5eb7564 100644
> --- a/arch/riscv/include/asm/cacheflush.h
> +++ b/arch/riscv/include/asm/cacheflush.h
> @@ -41,7 +41,7 @@ do {                                                  \
>  } while (0)
>
>  #ifdef CONFIG_64BIT
> -extern u64 new_vmalloc[NR_CPUS / sizeof(u64) + 1];
> +extern u64 new_valid_map_cpus[NR_CPUS / sizeof(u64) + 1];

new_valid_map_cpus is a bitmap, right? If so, you are allocating 8x
more memory than needed.
Can we use DECLARE_BITMAP instead?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DUQj%2BbdY2YojmfVf%3DqRQgCttD%3DPqE0h%3Dvm4pAbtNRP-uw%40mail.gmail.c=
om.

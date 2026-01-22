Return-Path: <kasan-dev+bncBC7OD3FKWUERBFE2Y3FQMGQEBNO4DTA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id KEPhJhaNcWkLJAAAu9opvQ
	(envelope-from <kasan-dev+bncBC7OD3FKWUERBFE2Y3FQMGQEBNO4DTA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 03:36:06 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb13b.google.com (mail-yx1-xb13b.google.com [IPv6:2607:f8b0:4864:20::b13b])
	by mail.lfdr.de (Postfix) with ESMTPS id F09C560FC0
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 03:36:05 +0100 (CET)
Received: by mail-yx1-xb13b.google.com with SMTP id 956f58d0204a3-6465127b44fsf1157525d50.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 18:36:05 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769049364; cv=pass;
        d=google.com; s=arc-20240605;
        b=jweLZUX5VUDV5gxwt4jHzFaH0de1LBz79/RTTzV02dHkb/DoFIua5LPR5W3PG8RUxa
         /61Gv/YaPG0B+2SLQwYPvoYBA7qHk/ZXtoBLqRmTgvAF6nnW4I00r9n45p4kENuRXUPg
         0ACzK+gM6IFYxi3d6GXGWGeY4RB0qqtTB2zbVRXWvj69MdtcxsLt4slmjp3oxZqoW6cm
         7+45FP0wdvOXpFZgjfHbG6PfWqQnh6ewVGGEPvL9KAYw77syCTaU8DC4Z0yUSb8N9YTv
         tgxI1V57xRjB5FTW3uLt4JiohQ/2+WlngG2RnClyC47dyalQ7v6Qd2mAvxysktmQyaCW
         q5Cw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zNge43JynjEOp3SZDmjDSJcIxg0/yLEFfnWNieURs+8=;
        fh=LpZlXnh6z8JyZbKoufagOH0eR1rt+UDtJuylY81ymRA=;
        b=gyMbH1A3jmwtaxRj0OyzTOBj5xuwXOkySoFp9fy4ZrrKbkKt4OL6FbPmHICXNv8Xr4
         qyBynq//ZM7HtwulLaCA022HX/wrQNbn/MtDajsDyk2jj10Y/rM6+QfDt46dl8x2gPSI
         Z2dZQqApF+FrE6b7+W+byjVwKyY8315IsBM62wqN3W0DRp+fJpAOoitS3ZsBzDvOYl96
         m78WfbUJVMNcPBP7PeGpoCCqrkubUCiqL2/iuKG/VSul0+cLF72IhsylzAd+st8KIFVE
         vVXEcrooWXmi7u1DO81Vd/s10VmDh+gr+oMmfRcpOnnoThIU5r9bOWgUShJLbEcEwW8X
         U9Wg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=DQEpPIJf;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::82a as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769049364; x=1769654164; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=zNge43JynjEOp3SZDmjDSJcIxg0/yLEFfnWNieURs+8=;
        b=Be8pvy7Tb6LavwPzvfysBmo5/xo/ouhsawilJ/Gafq69V3EuUFsCCaGJSCjlr+bCtj
         2qbTM/pypqFl9+h63X3dfJHjlh+7f6Jajwg0aZTeYXIgA4mwrFh6fETo6/pMmfBWWsf1
         3hE3ObbEp4w6hcKlzdcD0AFJ5E6CjTG9Wv49YLNNXfCv8H67koW7IxU5qz318Y8+Q07L
         lEesaGi0fdJBstvtbztNnLpwt/wU6VSIu/ZhtspXCjEYPqe8zxsN7ucd77duk4lUE3v6
         Ri/CBojO3uXHkWn38o/reX7Iuhk6Dgjla3Q3kHZjP2654LJV02dM0WrPbjLxWErQss7j
         dZpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769049364; x=1769654164;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=zNge43JynjEOp3SZDmjDSJcIxg0/yLEFfnWNieURs+8=;
        b=v/lHnJgeWK0rOxTMg0zhgggDvLGSBOGtJzMc3+sYFoGhSaymMzMZBgy8HfovnNbwhE
         kPx+oegU4uNvH4nwn+ve+rGwIxOgfKy2DQuHNZHCdicrhz4LhUXuJ5xhytp7397+DmoA
         2V0TXE+Rgq3WxBxOaIIDqej7rCANl5Iioq+VNmPKH7pH36C2EomxYbADakpyoK0/VOgR
         V3BeNLuPNw4puggrXzTm2TF0kZA0rDya0C65BWB4XUNgHsFBrlljIJAUYtQyPTjlsqDx
         p2hIXuNZThOduhMkBV4dAkjsjhePQt/ArVIil9I+P1a++syNHBihPOITxuMIwkn4olL6
         1Kow==
X-Forwarded-Encrypted: i=3; AJvYcCXVOhedeUrC9cNvYBBG7HTUUKU8UZmum9OtTYb1Wv5YABMl2XETRTv5zazakxLG42Wbs8Ryrw==@lfdr.de
X-Gm-Message-State: AOJu0YyoR87euXJi5cxkEZ8KOzbyECmsNX4c6CBGW1yCxayz+RIdlaYV
	PvWjkGbiXAvK1iv1sucKial62Kl5ityhfw8MY0YuycAX5DwxmnU+Dxlv
X-Received: by 2002:a05:690e:144c:b0:63f:b61a:71fb with SMTP id 956f58d0204a3-64951227acemr1290530d50.3.1769049364683;
        Wed, 21 Jan 2026 18:36:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HQqDq2cF5yzaul+YRIKrr6nE9R8IifuDzNtZnDXTdDtg=="
Received: by 2002:a53:b117:0:b0:648:f52d:75bf with SMTP id 956f58d0204a3-6495159d9bals265655d50.2.-pod-prod-00-us;
 Wed, 21 Jan 2026 18:36:03 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCUMiqDTo4V7bCX1bk2qTl11EUfySXiANmiyGioxhTv/Z3Kuz8US9TbcXVBG08loMYzCDuan379TPwg=@googlegroups.com
X-Received: by 2002:a53:b109:0:b0:645:527b:bc25 with SMTP id 956f58d0204a3-6495139be24mr1076070d50.43.1769049363690;
        Wed, 21 Jan 2026 18:36:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769049363; cv=pass;
        d=google.com; s=arc-20240605;
        b=OGFQtUJYTvjAl+i1u/TrH9tOgMTH4d66gJOGQKmTLt76N649vPkCAFDtAb0MwfWHr/
         juphfeoWz7QLCX0vBmc0sydDg85WlKdiiVg8RfbK6/uomVoepk2wUbU3/tILsbtK6tKn
         /saDw6poIEiZdMN8c5RR73RsVMTiN1pE7kTorpOdgRH40SEauTsHSiFILB/k02xgahtd
         RVt/qhFKP9SC2PzN42nxWdfi2u2tEN0vS7P/JRFHxc2j/s0zUeod5C6SGqaVkHjJ/L3k
         7EjRAv7jegsqtrIujU8LZ7yaFwQMrhlyia+d7iiECQS488gGfHhv/QfbAK8zXrY9Arm9
         OaEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=W1ztD/wqbKPGcB/OK5g1Xm5cGzV1LC64G0Uj3l4VYPc=;
        fh=at86BKBpNQbEKwGSJrILt5s4Nf9AJakfXN8g6gbItRc=;
        b=Qnj8a7oNVNR05KuZR0BNAkq94Zq3RQrFbPR1R9ZEjtUj1hfbcNJLzkQRvlsk9tY1ne
         VBrgUYiP2W/yt3QovwZjG3eWBomaNJx7X2HWSYK/BbtHYD7xGRoNYqdc+0ds4wkDpCWN
         8drWEQL3Q0+/KvgAARoPLok528H4gmrSYrGgq0peryLOWbPYbiGKr8RpfNUvwBUcnWxD
         h2C+Mge/2P6aXvM8faJX3Ebpob6BEoLYceO531hS6HGiMg5oDDXvmGG2ChUTsTGtDZ7Z
         b3LGPWXjcmTf0T0g0Z052JtsDG9r0CYYVOnHI+5+qlGw7bH88Cxfd1HKkQ89AFDDHy9B
         tRqQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=DQEpPIJf;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::82a as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x82a.google.com (mail-qt1-x82a.google.com. [2607:f8b0:4864:20::82a])
        by gmr-mx.google.com with ESMTPS id 956f58d0204a3-649170c4b5csi601682d50.7.2026.01.21.18.36.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Jan 2026 18:36:03 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::82a as permitted sender) client-ip=2607:f8b0:4864:20::82a;
Received: by mail-qt1-x82a.google.com with SMTP id d75a77b69052e-50299648ae9so104681cf.1
        for <kasan-dev@googlegroups.com>; Wed, 21 Jan 2026 18:36:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769049363; cv=none;
        d=google.com; s=arc-20240605;
        b=g4D0t3rNw9iKJZiWOBbkJeO2vOC0I8tdaq98mhGzhDRzEvhuQZpkDpfDXuNYeGLdQG
         7lsmvqGEXn8Cd3EHtvppL8KV0z3WmnDO2rVb1dJffNyEt1iRhREq6oYP2NuBDE8u1qPl
         YKMYH3od6/u2NBH3JOvpYeV1TsmoNjAnkSsoMdC3ASSHDZTa4RMGRxpJ4E1MSWAwYoZf
         DnP9Fz4AcLoYt2Nr4BLS0I2tQHTxC5A3cK4u6Kg0Sm7HaKPF4jBTBvG3sOfFtpapIiZv
         GIZcNcy3D3C+vKGL6GTWKbMY4D3OnKpY05DPZG/dvl5AHzrxQX4AnbQ1JecoTOGgpVnO
         8f3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=W1ztD/wqbKPGcB/OK5g1Xm5cGzV1LC64G0Uj3l4VYPc=;
        fh=at86BKBpNQbEKwGSJrILt5s4Nf9AJakfXN8g6gbItRc=;
        b=UzWwvk/VQtGU4xUhppN7LXoa5Rxa2S5OcqM9N1oa89139+hHtp8jK5wawOaMnwAsup
         H1nUiUPKB2TaJjWgna6Kq1HN3tHpLKeG5IpAtVtzeL40KDfkX5I6XyGQnLVSNS5Grffy
         NG79OOLtax2lHnBKWar5Dl/Q94yRkWtY8OmSncC71ktDhzBx2fCEsAptTyOjbBL4AQvK
         cAiC+6VtT2SMqNG1lXziKueehGQijdAyVe6P0u/dXALvgqAhMOjF9HhUqvTZUGYOEgfI
         er3co7r7ZK2LXh4QtM8vnFukqUrg6B07i7/chP+2McOrNHY8TAVtW4TMkzvwgJIUDYKa
         tRxg==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCWmNoNBzzU6gr/tw8mcsZkOkN31bQD79+xwrED8P2bIQ95Z/gy//PKJoETH0Gve90QVuTgHRK9B2F8=@googlegroups.com
X-Gm-Gg: AZuq6aIqdZro2nxl0WPxv3n8icnau4UYbvavd77TsYMOEPGPKpUPYIfw57qy6Xztrnh
	3jtT0x2m1kw9M3alNg366RaShAHdChFxkXqkmyobTe8JEcqSUNoe58fJh7Hw/XvMSqWoBlSFNou
	89PkEBkQ+RNKqbYY8tgV2/BLidRlhc3nGnDu9hNmQXYdAzSiHU4tT+IDelEurf/KkTOV1VljgSH
	PE9m7y4/LpnPUqSGUkRlkVQe+rUEMTIhsxCQ4qTgBF0vWO1/o6/nLyG5933BQMtszSnjQ==
X-Received: by 2002:ac8:7d13:0:b0:4f3:5474:3cb9 with SMTP id
 d75a77b69052e-502ebd66753mr6535371cf.14.1769049362800; Wed, 21 Jan 2026
 18:36:02 -0800 (PST)
MIME-Version: 1.0
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz> <20260116-sheaves-for-all-v3-21-5595cb000772@suse.cz>
In-Reply-To: <20260116-sheaves-for-all-v3-21-5595cb000772@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 21 Jan 2026 18:35:51 -0800
X-Gm-Features: AZwV_Qh9DJqdsygnR2vDEt2pFl_xN2VFuNuBwsJB6lM8tVfE5ettz4wsz-RroIY
Message-ID: <CAJuCfpHg9YfkVwtfCUvLH_0HNWzUgx1ekQ-QMyYBW_Qeqt=WjA@mail.gmail.com>
Subject: Re: [PATCH v3 21/21] mm/slub: cleanup and repurpose some stat items
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>, 
	Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>, 
	Andrew Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, 
	"Liam R. Howlett" <Liam.Howlett@oracle.com>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
	Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-rt-devel@lists.linux.dev, bpf@vger.kernel.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=DQEpPIJf;       arc=pass
 (i=1);       spf=pass (google.com: domain of surenb@google.com designates
 2607:f8b0:4864:20::82a as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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
X-Spamd-Result: default: False [-2.21 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	MISSING_XM_UA(0.00)[];
	MIME_TRACE(0.00)[0:+];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	TO_DN_SOME(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[17];
	TAGGED_RCPT(0.00)[kasan-dev];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	HAS_REPLYTO(0.00)[surenb@google.com];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	RCVD_COUNT_THREE(0.00)[4];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBC7OD3FKWUERBFE2Y3FQMGQEBNO4DTA];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[]
X-Rspamd-Queue-Id: F09C560FC0
X-Rspamd-Action: no action

On Fri, Jan 16, 2026 at 6:41=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> A number of stat items related to cpu slabs became unused, remove them.
>
> Two of those were ALLOC_FASTPATH and FREE_FASTPATH. But instead of
> removing those, use them instead of ALLOC_PCS and FREE_PCS, since
> sheaves are the new (and only) fastpaths, Remove the recently added
> _PCS variants instead.
>
> Change where FREE_SLOWPATH is counted so that it only counts freeing of
> objects by slab users that (for whatever reason) do not go to a percpu
> sheaf, and not all (including internal) callers of __slab_free(). Thus
> flushing sheaves (counted by SHEAF_FLUSH) no longer also increments
> FREE_SLOWPATH.

nit: I think I understand what you mean but "no longer also
increments" sounds wrong. Maybe repharase as "Thus sheaf flushing
(already counted by SHEAF_FLUSH) does not affect FREE_SLOWPATH
anymore."?

> This matches how ALLOC_SLOWPATH doesn't count sheaf
> refills (counted by SHEAF_REFILL).
>
> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slub.c | 77 +++++++++++++++++----------------------------------------=
------
>  1 file changed, 21 insertions(+), 56 deletions(-)
>
> diff --git a/mm/slub.c b/mm/slub.c
> index c12e90cb2fca..d73ad44fa046 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -330,33 +330,19 @@ enum add_mode {
>  };
>
>  enum stat_item {
> -       ALLOC_PCS,              /* Allocation from percpu sheaf */
> -       ALLOC_FASTPATH,         /* Allocation from cpu slab */
> -       ALLOC_SLOWPATH,         /* Allocation by getting a new cpu slab *=
/
> -       FREE_PCS,               /* Free to percpu sheaf */
> +       ALLOC_FASTPATH,         /* Allocation from percpu sheaves */
> +       ALLOC_SLOWPATH,         /* Allocation from partial or new slab */
>         FREE_RCU_SHEAF,         /* Free to rcu_free sheaf */
>         FREE_RCU_SHEAF_FAIL,    /* Failed to free to a rcu_free sheaf */
> -       FREE_FASTPATH,          /* Free to cpu slab */
> -       FREE_SLOWPATH,          /* Freeing not to cpu slab */
> +       FREE_FASTPATH,          /* Free to percpu sheaves */
> +       FREE_SLOWPATH,          /* Free to a slab */
>         FREE_ADD_PARTIAL,       /* Freeing moves slab to partial list */
>         FREE_REMOVE_PARTIAL,    /* Freeing removes last object */
> -       ALLOC_FROM_PARTIAL,     /* Cpu slab acquired from node partial li=
st */
> -       ALLOC_SLAB,             /* Cpu slab acquired from page allocator =
*/
> -       ALLOC_REFILL,           /* Refill cpu slab from slab freelist */
> -       ALLOC_NODE_MISMATCH,    /* Switching cpu slab */
> +       ALLOC_SLAB,             /* New slab acquired from page allocator =
*/
> +       ALLOC_NODE_MISMATCH,    /* Requested node different from cpu shea=
f */
>         FREE_SLAB,              /* Slab freed to the page allocator */
> -       CPUSLAB_FLUSH,          /* Abandoning of the cpu slab */
> -       DEACTIVATE_FULL,        /* Cpu slab was full when deactivated */
> -       DEACTIVATE_EMPTY,       /* Cpu slab was empty when deactivated */
> -       DEACTIVATE_REMOTE_FREES,/* Slab contained remotely freed objects =
*/
> -       DEACTIVATE_BYPASS,      /* Implicit deactivation */
>         ORDER_FALLBACK,         /* Number of times fallback was necessary=
 */
> -       CMPXCHG_DOUBLE_CPU_FAIL,/* Failures of this_cpu_cmpxchg_double */
>         CMPXCHG_DOUBLE_FAIL,    /* Failures of slab freelist update */
> -       CPU_PARTIAL_ALLOC,      /* Used cpu partial on alloc */
> -       CPU_PARTIAL_FREE,       /* Refill cpu partial on free */
> -       CPU_PARTIAL_NODE,       /* Refill cpu partial from node partial *=
/
> -       CPU_PARTIAL_DRAIN,      /* Drain cpu partial to node partial */
>         SHEAF_FLUSH,            /* Objects flushed from a sheaf */
>         SHEAF_REFILL,           /* Objects refilled to a sheaf */
>         SHEAF_ALLOC,            /* Allocation of an empty sheaf */
> @@ -4347,8 +4333,10 @@ void *alloc_from_pcs(struct kmem_cache *s, gfp_t g=
fp, int node)
>          * We assume the percpu sheaves contain only local objects althou=
gh it's
>          * not completely guaranteed, so we verify later.
>          */
> -       if (unlikely(node_requested && node !=3D numa_mem_id()))
> +       if (unlikely(node_requested && node !=3D numa_mem_id())) {
> +               stat(s, ALLOC_NODE_MISMATCH);
>                 return NULL;
> +       }
>
>         if (!local_trylock(&s->cpu_sheaves->lock))
>                 return NULL;
> @@ -4371,6 +4359,7 @@ void *alloc_from_pcs(struct kmem_cache *s, gfp_t gf=
p, int node)
>                  */
>                 if (page_to_nid(virt_to_page(object)) !=3D node) {
>                         local_unlock(&s->cpu_sheaves->lock);
> +                       stat(s, ALLOC_NODE_MISMATCH);
>                         return NULL;
>                 }
>         }
> @@ -4379,7 +4368,7 @@ void *alloc_from_pcs(struct kmem_cache *s, gfp_t gf=
p, int node)
>
>         local_unlock(&s->cpu_sheaves->lock);
>
> -       stat(s, ALLOC_PCS);
> +       stat(s, ALLOC_FASTPATH);
>
>         return object;
>  }
> @@ -4451,7 +4440,7 @@ unsigned int alloc_from_pcs_bulk(struct kmem_cache =
*s, gfp_t gfp, size_t size,
>
>         local_unlock(&s->cpu_sheaves->lock);
>
> -       stat_add(s, ALLOC_PCS, batch);
> +       stat_add(s, ALLOC_FASTPATH, batch);
>
>         allocated +=3D batch;
>
> @@ -5111,8 +5100,6 @@ static void __slab_free(struct kmem_cache *s, struc=
t slab *slab,
>         unsigned long flags;
>         bool on_node_partial;
>
> -       stat(s, FREE_SLOWPATH);

After moving the above accounting to the callers I think there are
several callers which won't account it anymore:
- free_deferred_objects
- memcg_alloc_abort_single
- slab_free_after_rcu_debug
- ___cache_free

Am I missing something or is that intentional?

> -
>         if (IS_ENABLED(CONFIG_SLUB_TINY) || kmem_cache_debug(s)) {
>                 free_to_partial_list(s, slab, head, tail, cnt, addr);
>                 return;
> @@ -5416,7 +5403,7 @@ bool free_to_pcs(struct kmem_cache *s, void *object=
, bool allow_spin)
>
>         local_unlock(&s->cpu_sheaves->lock);
>
> -       stat(s, FREE_PCS);
> +       stat(s, FREE_FASTPATH);
>
>         return true;
>  }
> @@ -5664,7 +5651,7 @@ static void free_to_pcs_bulk(struct kmem_cache *s, =
size_t size, void **p)
>
>         local_unlock(&s->cpu_sheaves->lock);
>
> -       stat_add(s, FREE_PCS, batch);
> +       stat_add(s, FREE_FASTPATH, batch);
>
>         if (batch < size) {
>                 p +=3D batch;
> @@ -5686,10 +5673,12 @@ static void free_to_pcs_bulk(struct kmem_cache *s=
, size_t size, void **p)
>          */
>  fallback:
>         __kmem_cache_free_bulk(s, size, p);
> +       stat_add(s, FREE_SLOWPATH, size);
>
>  flush_remote:
>         if (remote_nr) {
>                 __kmem_cache_free_bulk(s, remote_nr, &remote_objects[0]);
> +               stat_add(s, FREE_SLOWPATH, remote_nr);
>                 if (i < size) {
>                         remote_nr =3D 0;
>                         goto next_remote_batch;
> @@ -5784,6 +5773,7 @@ void slab_free(struct kmem_cache *s, struct slab *s=
lab, void *object,
>         }
>
>         __slab_free(s, slab, object, object, 1, addr);
> +       stat(s, FREE_SLOWPATH);
>  }
>
>  #ifdef CONFIG_MEMCG
> @@ -5806,8 +5796,10 @@ void slab_free_bulk(struct kmem_cache *s, struct s=
lab *slab, void *head,
>          * With KASAN enabled slab_free_freelist_hook modifies the freeli=
st
>          * to remove objects, whose reuse must be delayed.
>          */
> -       if (likely(slab_free_freelist_hook(s, &head, &tail, &cnt)))
> +       if (likely(slab_free_freelist_hook(s, &head, &tail, &cnt))) {
>                 __slab_free(s, slab, head, tail, cnt, addr);
> +               stat_add(s, FREE_SLOWPATH, cnt);
> +       }
>  }
>
>  #ifdef CONFIG_SLUB_RCU_DEBUG
> @@ -6705,6 +6697,7 @@ int __kmem_cache_alloc_bulk(struct kmem_cache *s, g=
fp_t flags, size_t size,
>                 i =3D refill_objects(s, p, flags, size, size);
>                 if (i < size)
>                         goto error;
> +               stat_add(s, ALLOC_SLOWPATH, i);
>         }
>
>         return i;
> @@ -8704,33 +8697,19 @@ static ssize_t text##_store(struct kmem_cache *s,=
               \
>  }                                                              \
>  SLAB_ATTR(text);                                               \
>
> -STAT_ATTR(ALLOC_PCS, alloc_cpu_sheaf);
>  STAT_ATTR(ALLOC_FASTPATH, alloc_fastpath);
>  STAT_ATTR(ALLOC_SLOWPATH, alloc_slowpath);
> -STAT_ATTR(FREE_PCS, free_cpu_sheaf);
>  STAT_ATTR(FREE_RCU_SHEAF, free_rcu_sheaf);
>  STAT_ATTR(FREE_RCU_SHEAF_FAIL, free_rcu_sheaf_fail);
>  STAT_ATTR(FREE_FASTPATH, free_fastpath);
>  STAT_ATTR(FREE_SLOWPATH, free_slowpath);
>  STAT_ATTR(FREE_ADD_PARTIAL, free_add_partial);
>  STAT_ATTR(FREE_REMOVE_PARTIAL, free_remove_partial);
> -STAT_ATTR(ALLOC_FROM_PARTIAL, alloc_from_partial);
>  STAT_ATTR(ALLOC_SLAB, alloc_slab);
> -STAT_ATTR(ALLOC_REFILL, alloc_refill);
>  STAT_ATTR(ALLOC_NODE_MISMATCH, alloc_node_mismatch);
>  STAT_ATTR(FREE_SLAB, free_slab);
> -STAT_ATTR(CPUSLAB_FLUSH, cpuslab_flush);
> -STAT_ATTR(DEACTIVATE_FULL, deactivate_full);
> -STAT_ATTR(DEACTIVATE_EMPTY, deactivate_empty);
> -STAT_ATTR(DEACTIVATE_REMOTE_FREES, deactivate_remote_frees);
> -STAT_ATTR(DEACTIVATE_BYPASS, deactivate_bypass);
>  STAT_ATTR(ORDER_FALLBACK, order_fallback);
> -STAT_ATTR(CMPXCHG_DOUBLE_CPU_FAIL, cmpxchg_double_cpu_fail);
>  STAT_ATTR(CMPXCHG_DOUBLE_FAIL, cmpxchg_double_fail);
> -STAT_ATTR(CPU_PARTIAL_ALLOC, cpu_partial_alloc);
> -STAT_ATTR(CPU_PARTIAL_FREE, cpu_partial_free);
> -STAT_ATTR(CPU_PARTIAL_NODE, cpu_partial_node);
> -STAT_ATTR(CPU_PARTIAL_DRAIN, cpu_partial_drain);
>  STAT_ATTR(SHEAF_FLUSH, sheaf_flush);
>  STAT_ATTR(SHEAF_REFILL, sheaf_refill);
>  STAT_ATTR(SHEAF_ALLOC, sheaf_alloc);
> @@ -8806,33 +8785,19 @@ static struct attribute *slab_attrs[] =3D {
>         &remote_node_defrag_ratio_attr.attr,
>  #endif
>  #ifdef CONFIG_SLUB_STATS
> -       &alloc_cpu_sheaf_attr.attr,
>         &alloc_fastpath_attr.attr,
>         &alloc_slowpath_attr.attr,
> -       &free_cpu_sheaf_attr.attr,
>         &free_rcu_sheaf_attr.attr,
>         &free_rcu_sheaf_fail_attr.attr,
>         &free_fastpath_attr.attr,
>         &free_slowpath_attr.attr,
>         &free_add_partial_attr.attr,
>         &free_remove_partial_attr.attr,
> -       &alloc_from_partial_attr.attr,
>         &alloc_slab_attr.attr,
> -       &alloc_refill_attr.attr,
>         &alloc_node_mismatch_attr.attr,
>         &free_slab_attr.attr,
> -       &cpuslab_flush_attr.attr,
> -       &deactivate_full_attr.attr,
> -       &deactivate_empty_attr.attr,
> -       &deactivate_remote_frees_attr.attr,
> -       &deactivate_bypass_attr.attr,
>         &order_fallback_attr.attr,
>         &cmpxchg_double_fail_attr.attr,
> -       &cmpxchg_double_cpu_fail_attr.attr,
> -       &cpu_partial_alloc_attr.attr,
> -       &cpu_partial_free_attr.attr,
> -       &cpu_partial_node_attr.attr,
> -       &cpu_partial_drain_attr.attr,
>         &sheaf_flush_attr.attr,
>         &sheaf_refill_attr.attr,
>         &sheaf_alloc_attr.attr,
>
> --
> 2.52.0
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AJuCfpHg9YfkVwtfCUvLH_0HNWzUgx1ekQ-QMyYBW_Qeqt%3DWjA%40mail.gmail.com.

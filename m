Return-Path: <kasan-dev+bncBC7OD3FKWUERBZMBYDFQMGQEHXGKEHI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 0C2THugAcGmUUgAAu9opvQ
	(envelope-from <kasan-dev+bncBC7OD3FKWUERBZMBYDFQMGQEHXGKEHI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 23:25:44 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id DD3644CEF0
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 23:25:43 +0100 (CET)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-34c93f0849dsf220145a91.1
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 14:25:43 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768947942; cv=pass;
        d=google.com; s=arc-20240605;
        b=VehSkPu+kQbhlT+iQd0M+eU+51pvoE+7fkq1jkC0hrDND+k2qs5IrUA82Yc8l+V7eM
         moVIfGTfQXq9gqpmLmMhlzgyulreNgANzyzyX4j8lFHMAgMocwion85/fQfx9j+AAJgO
         mSl0cfkn2wz/tZJjw7rLSme48PjyXScBxOZ9ttLPzbmaWKUSTIQ4USROOUhgXmG16KIv
         xeh9odiqOxksMftc6d2ZAsGDQCCk3Grlb8wLd2GpiZ7HBfpxIAgKLxPtbRQjJdPhKqwm
         s2LnM4DEmMQNQ/3XV4q+v5lWI+dFC995aOAzuFr99eCRb2OGioD34G41VOwfc1o2G5s/
         /gAg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MYt3nTe56lPXgDzz85e3ALtmzRqVO1Eo6PUmJ4chcRU=;
        fh=d1fBPVvkl7GgCwNJEdNTiimvvlaNgFIFVJQ+y6yi+J4=;
        b=QWp8+vdP2wRfIXxtaz+X2vfoVjTqz/LlJgV47r3aTL6g8VAzjev1QLlHJt1TeC8aj9
         BE/Mez/u6OExvzlvDldvF3wJmUDFX+Q+WkXdgagsoehku3t08Z5b0TL+IgASccv27DEt
         CMbdYlYruTeksJIVIgSbd0ALMYiCdrni47LiRQyhhO+v4IE4aZSJbgdMK/gHNMmtEMTH
         LzlaHyqJOiJT2wlutv+C/9n8ojtSBtMGfPtDKb+9c+GUiX2KEPMuyfrGa+y77G6JI83r
         vhOMaAUqP9qzJDqlZ94iSzKbblB8LJJyRELCvFntwV4DHXXmnz5UW1Tu91m+rnKhr1hY
         V9zg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=v6NZiOQT;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::82b as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768947942; x=1769552742; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=MYt3nTe56lPXgDzz85e3ALtmzRqVO1Eo6PUmJ4chcRU=;
        b=HoLm06O0APTB22k37+TYxTDItiMLp9t6VwqEBnFLkeO2uB8JKWecve1Ct7w838XIxc
         yKaArD7fqoHjSAkmiK6LXYoVN+u2urpiy215FqKSkhFvbtGZMqHs0pKEpfyOhA8m/L8P
         74qaKHmgW5vapL0Y4iJalDjoaWEsfdz6T9cEaGMzQGKvMg3W9YirBEePnx5wPjkecoyV
         8Rn07v1O8BKQc45eFQ8k6ZUYMRqby2rt6ftChJXWT5tplya5N8y9jK+KypzCveZj7U/E
         1GLymz1QHH/skT8nDy2LqyAQiBag7pyHFyWSHB+rA68MmOZTelXYBcuEMeV57vrijvb+
         ON8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768947942; x=1769552742;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=MYt3nTe56lPXgDzz85e3ALtmzRqVO1Eo6PUmJ4chcRU=;
        b=AScrGakyaj/ctAJ55a/LHMsGkj66ZWHd+KFtIp60eo+XoFA8q/Z/U5gFoES5kBMuga
         crThzLZB5nxbZPL14Tvyxq6NJZEWxfijNvRFxy+NUI9IhSu/3PjnhRI02ZTRuFwp/Uzt
         SnKSGecxiFkuuVyadzJVBoE8YeOC5jpytlUd7PmHLFjUAheRXkhvoAGqCwuQtcBlF0FC
         nsGZf3FUztFX2W9sqjq7pUN4OzKYZ0vE+yYADIWKnUkkLN2iZ5VrTRH0x87O8ITodtZe
         UaIBe3qFp3wD8ItgnD6UtFSAjYD+AW2ppFZ8lRAdbHEMa7nsAbslWF9gWkcM2qRXQ588
         aUkw==
X-Forwarded-Encrypted: i=3; AJvYcCXEZA6P4rt39wK+j/ZgCRdJG6ylL9XO9BQbV5RXUNMT0oO1MZcouVXzAB/mKuzXhnBSCIT+FA==@lfdr.de
X-Gm-Message-State: AOJu0Yyqm84RLNMHQ5YYzeQa7H/VMgeoHuV+xecDtzm5gDtf9xzzz6ni
	BQWPC5sTt4U6Jn4nLglZ/IthfFTXiXYfX6OhqqP/J6Zn/UVV5yZG8HP0
X-Received: by 2002:a17:90b:53d0:b0:349:162d:ae0c with SMTP id 98e67ed59e1d1-35272bcb853mr13175051a91.4.1768947941869;
        Tue, 20 Jan 2026 14:25:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+E9oafkaKt/E02xmFbjW0PYZgxRwknVu4HtqAPpvw24BA=="
Received: by 2002:a17:90b:3a90:b0:34c:3502:8aca with SMTP id
 98e67ed59e1d1-352fa9b5f23ls135247a91.0.-pod-prod-00-us-canary; Tue, 20 Jan
 2026 14:25:40 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCV43crr7JMSeHEgE5EihXtjh5H/vWCp87J1LZvS6/TYXdeVT0NqKP9T8ihzqTcrw35ezkkyf8EhmU4=@googlegroups.com
X-Received: by 2002:a17:90b:224d:b0:352:ece8:1f6c with SMTP id 98e67ed59e1d1-352ece82c4emr1136601a91.8.1768947940433;
        Tue, 20 Jan 2026 14:25:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768947940; cv=pass;
        d=google.com; s=arc-20240605;
        b=Gp0pC0Yf6b23/pPMp2bhJ+bJs2do+Ltcc+9hlDxqCoROX18yM8z8durd1QHsxKKwOz
         yyJ+6swwQgnW/LYlaLhOmKR/3PspOOAbj2fq2LESz4a6KSPhZ3CQVda5UQ3aZut4zYdo
         iEv0nrfMZePwOyG4k1ZDdkJOcmde32+R2dHZuX4cYHfLpLH7DUj97cXW/9NQTncRvMfI
         n41jMyvC9BEWPhxwW2w53YDMqX0TEjOGgKEotygQVxre7L/hQNUBws+zurnaoPyUm17g
         B9hk9ynmo4WeH2rk+xkdW0SbbcBwbaPthdPKDO9qfMhI93OTe90tHSLC2NpoQ/herxKi
         6y5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=44dOOwNB1nzUj6Js371cPSz9QaCzmdjxiuuzpRwtXwc=;
        fh=uDrOZElOsxPuygZ2rB/kM231n6Y8CCgao7QuEn1RVkk=;
        b=NPnF+PngnNlyNXWJEnQl/4XoGq2Yx0ZXhR+BKxrS//3R/1/ZcKHPnWU4YXv+iaiJ8Q
         4HZEJ+2mAmc72irlT9aJQZpFw95eeQ5DFjLUnYA1Rott5Tzw1ZlTtWoAwMKQGnw02lxn
         FOFuIVDbfi+t+q/ZSzIXvF5tzxiYT09zqKA9Ruf/DTDuCctQsfLgDkAxPmxRD8xG8TaZ
         vc0CeD2DYODHkP9rFvi/hSW87teX4X4hBVZ05EeZwxvPEOyGUc3yxt3eb6vWhzb32w/C
         X/jpi4t58DRDjzoVcTMdUNRh41jqO360+SgSPYr0lQYsxxqv8qdtNI8BDyJgeKPMGYl8
         9VtA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=v6NZiOQT;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::82b as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x82b.google.com (mail-qt1-x82b.google.com. [2607:f8b0:4864:20::82b])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2a71919eaa1si5133835ad.6.2026.01.20.14.25.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Jan 2026 14:25:40 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::82b as permitted sender) client-ip=2607:f8b0:4864:20::82b;
Received: by mail-qt1-x82b.google.com with SMTP id d75a77b69052e-5014b5d8551so54701cf.0
        for <kasan-dev@googlegroups.com>; Tue, 20 Jan 2026 14:25:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768947939; cv=none;
        d=google.com; s=arc-20240605;
        b=KDETYVVVxap2BgGo2eGpwSQN62D8bQ5nsgCcHwUQPoJuc5lodoWOuiBzy2d0gZZ//u
         oMcaujSwI2mFUv8DhVfM+X5q5oF4hgXKyvhGuNTINWlZQVHQKBCTGFVnSAeC7EfldwAP
         h1uRJpspcAYnov+DD9hBmdMBIZEnlnqPejNHYCLodj0fPRgKVaV7SD3PcdAY/X+th8z3
         CGtG4YnIJU9OK18yZh6rqVHxaxytmYCYXL+A/0LHjCIilhSJUHI/hZLkzK0bv7ueRlBw
         C9Afv1qhexWMwZHaK1IUHhu/VnEIBvg668/qQTFvKAdSOp253+VLvHMuN01+7QkCiVIi
         x4Cw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=44dOOwNB1nzUj6Js371cPSz9QaCzmdjxiuuzpRwtXwc=;
        fh=uDrOZElOsxPuygZ2rB/kM231n6Y8CCgao7QuEn1RVkk=;
        b=MZD7uX+6WY7LYFQwk7+ax6AaewnzXiUKGdmEN2k7fnE5XpUUX0sMfkvdPq6ug02fYa
         ifPUsDmkoYNvfocYkiY6DvOoJPAF4zK3gNIhIHPazpeH17l3/V2AOe2zR1xFhYt6OH+l
         aVLpnV8Vg2wNAKMbHJcOeDRU29JzG9FDbXvqwMA+ourV3BainaXsuxXy6HKUKWA6lQJF
         sE81yn5FVuqANHxpiCYzgcvvfwNH9PcfS2k9AhyS5Jg8W2LVCh8k8UPwE+ZYJaLMznYz
         JijlgtNc5quFN4VEDHAGcgmHoWeN2Tj7XswuwtO1Q4sVPG9QI1ac0/EPLYUY5zotNf6b
         yEjQ==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCXZja7EE+gYtTiD9uIi7UyawGsPBNA1gD9G3U+/pVmm5ySmAMKtbPTHYeUwpCwg5dP1TgUnloG3zHo=@googlegroups.com
X-Gm-Gg: AY/fxX5wytnYlZKiYq+H1VpcNEqiO1CH0B5wZVBSh5B5pY44hqKk8d1VCMXVoXAjjOy
	XBIZYP6z3K9QjafxU9I83AlnNi08dJsLKyKxmIWMLHNKYM77QOWgvJgsr5K7+j5A1aNvtJuTxqV
	ocDXYkWd7gWF2Pq5bSGr/TCz3U90bhOsLAE4DaardV4C2gW5fJoqkP3JdLfnNZUzBULqOvXckjS
	oeduTLuxOpcEzbPG9ZG6sDCqYe391LAA0O66SMGqqtqM95PXIj4SDbXZd/C8KLl2W6DvUzpsoJ2
	RnDJJGs7OHhWTKf4DADtjqQ=
X-Received: by 2002:a05:622a:1181:b0:4ed:ff77:1a85 with SMTP id
 d75a77b69052e-502e1ab389cmr1281971cf.17.1768947938936; Tue, 20 Jan 2026
 14:25:38 -0800 (PST)
MIME-Version: 1.0
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz> <20260116-sheaves-for-all-v3-11-5595cb000772@suse.cz>
In-Reply-To: <20260116-sheaves-for-all-v3-11-5595cb000772@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 20 Jan 2026 22:25:27 +0000
X-Gm-Features: AZwV_QgM-BqnduoA5RFORFxa5mM3qHJ9TZZetAs0zM1kLzOUnwUT9c3G3wjCAp8
Message-ID: <CAJuCfpHaSg2O0vZhfAD+61i7Vq=T3OeQ=NXirXMd-2GCKRAgjg@mail.gmail.com>
Subject: Re: [PATCH v3 11/21] slab: remove SLUB_CPU_PARTIAL
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
 header.i=@google.com header.s=20230601 header.b=v6NZiOQT;       arc=pass
 (i=1);       spf=pass (google.com: domain of surenb@google.com designates
 2607:f8b0:4864:20::82b as permitted sender) smtp.mailfrom=surenb@google.com;
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
X-Spamd-Result: default: False [-2.21 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBC7OD3FKWUERBZMBYDFQMGQEHXGKEHI];
	RCVD_COUNT_THREE(0.00)[4];
	FROM_HAS_DN(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[17];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	HAS_REPLYTO(0.00)[surenb@google.com];
	TAGGED_RCPT(0.00)[kasan-dev];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email,mail.gmail.com:mid,googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: DD3644CEF0
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Fri, Jan 16, 2026 at 2:40=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> We have removed the partial slab usage from allocation paths. Now remove
> the whole config option and associated code.
>
> Reviewed-by: Suren Baghdasaryan <surenb@google.com>

I did? Well, if so, I missed some remaining mentions about cpu partial cach=
es:
- slub.c has several hits on "cpu partial" in the comments.
- there is one hit on "put_cpu_partial" in slub.c in the comments.

Should we also update Documentation/ABI/testing/sysfs-kernel-slab to
say that from now on cpu_partial control always reads 0?

Once addressed, please feel free to keep my Reviewed-by.

> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/Kconfig |  11 ---
>  mm/slab.h  |  29 ------
>  mm/slub.c  | 321 ++++---------------------------------------------------=
------
>  3 files changed, 19 insertions(+), 342 deletions(-)
>
> diff --git a/mm/Kconfig b/mm/Kconfig
> index bd0ea5454af8..08593674cd20 100644
> --- a/mm/Kconfig
> +++ b/mm/Kconfig
> @@ -247,17 +247,6 @@ config SLUB_STATS
>           out which slabs are relevant to a particular load.
>           Try running: slabinfo -DA
>
> -config SLUB_CPU_PARTIAL
> -       default y
> -       depends on SMP && !SLUB_TINY
> -       bool "Enable per cpu partial caches"
> -       help
> -         Per cpu partial caches accelerate objects allocation and freein=
g
> -         that is local to a processor at the price of more indeterminism
> -         in the latency of the free. On overflow these caches will be cl=
eared
> -         which requires the taking of locks that may cause latency spike=
s.
> -         Typically one would choose no for a realtime system.
> -
>  config RANDOM_KMALLOC_CACHES
>         default n
>         depends on !SLUB_TINY
> diff --git a/mm/slab.h b/mm/slab.h
> index cb48ce5014ba..e77260720994 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -77,12 +77,6 @@ struct slab {
>                                         struct llist_node llnode;
>                                         void *flush_freelist;
>                                 };
> -#ifdef CONFIG_SLUB_CPU_PARTIAL
> -                               struct {
> -                                       struct slab *next;
> -                                       int slabs;      /* Nr of slabs le=
ft */
> -                               };
> -#endif
>                         };
>                         /* Double-word boundary */
>                         struct freelist_counters;
> @@ -188,23 +182,6 @@ static inline size_t slab_size(const struct slab *sl=
ab)
>         return PAGE_SIZE << slab_order(slab);
>  }
>
> -#ifdef CONFIG_SLUB_CPU_PARTIAL
> -#define slub_percpu_partial(c)                 ((c)->partial)
> -
> -#define slub_set_percpu_partial(c, p)          \
> -({                                             \
> -       slub_percpu_partial(c) =3D (p)->next;     \
> -})
> -
> -#define slub_percpu_partial_read_once(c)       READ_ONCE(slub_percpu_par=
tial(c))
> -#else
> -#define slub_percpu_partial(c)                 NULL
> -
> -#define slub_set_percpu_partial(c, p)
> -
> -#define slub_percpu_partial_read_once(c)       NULL
> -#endif // CONFIG_SLUB_CPU_PARTIAL
> -
>  /*
>   * Word size structure that can be atomically updated or read and that
>   * contains both the order and the number of objects that a slab of the
> @@ -228,12 +205,6 @@ struct kmem_cache {
>         unsigned int object_size;       /* Object size without metadata *=
/
>         struct reciprocal_value reciprocal_size;
>         unsigned int offset;            /* Free pointer offset */
> -#ifdef CONFIG_SLUB_CPU_PARTIAL
> -       /* Number of per cpu partial objects to keep around */
> -       unsigned int cpu_partial;
> -       /* Number of per cpu partial slabs to keep around */
> -       unsigned int cpu_partial_slabs;
> -#endif
>         unsigned int sheaf_capacity;
>         struct kmem_cache_order_objects oo;
>
> diff --git a/mm/slub.c b/mm/slub.c
> index 698c0d940f06..6b1280f7900a 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -263,15 +263,6 @@ void *fixup_red_left(struct kmem_cache *s, void *p)
>         return p;
>  }
>
> -static inline bool kmem_cache_has_cpu_partial(struct kmem_cache *s)
> -{
> -#ifdef CONFIG_SLUB_CPU_PARTIAL
> -       return !kmem_cache_debug(s);
> -#else
> -       return false;
> -#endif
> -}
> -
>  /*
>   * Issues still to be resolved:
>   *
> @@ -426,9 +417,6 @@ struct freelist_tid {
>  struct kmem_cache_cpu {
>         struct freelist_tid;
>         struct slab *slab;      /* The slab from which we are allocating =
*/
> -#ifdef CONFIG_SLUB_CPU_PARTIAL
> -       struct slab *partial;   /* Partially allocated slabs */
> -#endif
>         local_trylock_t lock;   /* Protects the fields above */
>  #ifdef CONFIG_SLUB_STATS
>         unsigned int stat[NR_SLUB_STAT_ITEMS];
> @@ -673,29 +661,6 @@ static inline unsigned int oo_objects(struct kmem_ca=
che_order_objects x)
>         return x.x & OO_MASK;
>  }
>
> -#ifdef CONFIG_SLUB_CPU_PARTIAL
> -static void slub_set_cpu_partial(struct kmem_cache *s, unsigned int nr_o=
bjects)
> -{
> -       unsigned int nr_slabs;
> -
> -       s->cpu_partial =3D nr_objects;
> -
> -       /*
> -        * We take the number of objects but actually limit the number of
> -        * slabs on the per cpu partial list, in order to limit excessive
> -        * growth of the list. For simplicity we assume that the slabs wi=
ll
> -        * be half-full.
> -        */
> -       nr_slabs =3D DIV_ROUND_UP(nr_objects * 2, oo_objects(s->oo));
> -       s->cpu_partial_slabs =3D nr_slabs;
> -}
> -#elif defined(SLAB_SUPPORTS_SYSFS)
> -static inline void
> -slub_set_cpu_partial(struct kmem_cache *s, unsigned int nr_objects)
> -{
> -}
> -#endif /* CONFIG_SLUB_CPU_PARTIAL */
> -
>  /*
>   * If network-based swap is enabled, slub must keep track of whether mem=
ory
>   * were allocated from pfmemalloc reserves.
> @@ -3474,12 +3439,6 @@ static void *alloc_single_from_new_slab(struct kme=
m_cache *s, struct slab *slab,
>         return object;
>  }
>
> -#ifdef CONFIG_SLUB_CPU_PARTIAL
> -static void put_cpu_partial(struct kmem_cache *s, struct slab *slab, int=
 drain);
> -#else
> -static inline void put_cpu_partial(struct kmem_cache *s, struct slab *sl=
ab,
> -                                  int drain) { }
> -#endif
>  static inline bool pfmemalloc_match(struct slab *slab, gfp_t gfpflags);
>
>  static bool get_partial_node_bulk(struct kmem_cache *s,
> @@ -3898,131 +3857,6 @@ static void deactivate_slab(struct kmem_cache *s,=
 struct slab *slab,
>  #define local_unlock_cpu_slab(s, flags)        \
>         local_unlock_irqrestore(&(s)->cpu_slab->lock, flags)
>
> -#ifdef CONFIG_SLUB_CPU_PARTIAL
> -static void __put_partials(struct kmem_cache *s, struct slab *partial_sl=
ab)
> -{
> -       struct kmem_cache_node *n =3D NULL, *n2 =3D NULL;
> -       struct slab *slab, *slab_to_discard =3D NULL;
> -       unsigned long flags =3D 0;
> -
> -       while (partial_slab) {
> -               slab =3D partial_slab;
> -               partial_slab =3D slab->next;
> -
> -               n2 =3D get_node(s, slab_nid(slab));
> -               if (n !=3D n2) {
> -                       if (n)
> -                               spin_unlock_irqrestore(&n->list_lock, fla=
gs);
> -
> -                       n =3D n2;
> -                       spin_lock_irqsave(&n->list_lock, flags);
> -               }
> -
> -               if (unlikely(!slab->inuse && n->nr_partial >=3D s->min_pa=
rtial)) {
> -                       slab->next =3D slab_to_discard;
> -                       slab_to_discard =3D slab;
> -               } else {
> -                       add_partial(n, slab, DEACTIVATE_TO_TAIL);
> -                       stat(s, FREE_ADD_PARTIAL);
> -               }
> -       }
> -
> -       if (n)
> -               spin_unlock_irqrestore(&n->list_lock, flags);
> -
> -       while (slab_to_discard) {
> -               slab =3D slab_to_discard;
> -               slab_to_discard =3D slab_to_discard->next;
> -
> -               stat(s, DEACTIVATE_EMPTY);
> -               discard_slab(s, slab);
> -               stat(s, FREE_SLAB);
> -       }
> -}
> -
> -/*
> - * Put all the cpu partial slabs to the node partial list.
> - */
> -static void put_partials(struct kmem_cache *s)
> -{
> -       struct slab *partial_slab;
> -       unsigned long flags;
> -
> -       local_lock_irqsave(&s->cpu_slab->lock, flags);
> -       partial_slab =3D this_cpu_read(s->cpu_slab->partial);
> -       this_cpu_write(s->cpu_slab->partial, NULL);
> -       local_unlock_irqrestore(&s->cpu_slab->lock, flags);
> -
> -       if (partial_slab)
> -               __put_partials(s, partial_slab);
> -}
> -
> -static void put_partials_cpu(struct kmem_cache *s,
> -                            struct kmem_cache_cpu *c)
> -{
> -       struct slab *partial_slab;
> -
> -       partial_slab =3D slub_percpu_partial(c);
> -       c->partial =3D NULL;
> -
> -       if (partial_slab)
> -               __put_partials(s, partial_slab);
> -}
> -
> -/*
> - * Put a slab into a partial slab slot if available.
> - *
> - * If we did not find a slot then simply move all the partials to the
> - * per node partial list.
> - */
> -static void put_cpu_partial(struct kmem_cache *s, struct slab *slab, int=
 drain)
> -{
> -       struct slab *oldslab;
> -       struct slab *slab_to_put =3D NULL;
> -       unsigned long flags;
> -       int slabs =3D 0;
> -
> -       local_lock_cpu_slab(s, flags);
> -
> -       oldslab =3D this_cpu_read(s->cpu_slab->partial);
> -
> -       if (oldslab) {
> -               if (drain && oldslab->slabs >=3D s->cpu_partial_slabs) {
> -                       /*
> -                        * Partial array is full. Move the existing set t=
o the
> -                        * per node partial list. Postpone the actual unf=
reezing
> -                        * outside of the critical section.
> -                        */
> -                       slab_to_put =3D oldslab;
> -                       oldslab =3D NULL;
> -               } else {
> -                       slabs =3D oldslab->slabs;
> -               }
> -       }
> -
> -       slabs++;
> -
> -       slab->slabs =3D slabs;
> -       slab->next =3D oldslab;
> -
> -       this_cpu_write(s->cpu_slab->partial, slab);
> -
> -       local_unlock_cpu_slab(s, flags);
> -
> -       if (slab_to_put) {
> -               __put_partials(s, slab_to_put);
> -               stat(s, CPU_PARTIAL_DRAIN);
> -       }
> -}
> -
> -#else  /* CONFIG_SLUB_CPU_PARTIAL */
> -
> -static inline void put_partials(struct kmem_cache *s) { }
> -static inline void put_partials_cpu(struct kmem_cache *s,
> -                                   struct kmem_cache_cpu *c) { }
> -
> -#endif /* CONFIG_SLUB_CPU_PARTIAL */
> -
>  static inline void flush_slab(struct kmem_cache *s, struct kmem_cache_cp=
u *c)
>  {
>         unsigned long flags;
> @@ -4060,8 +3894,6 @@ static inline void __flush_cpu_slab(struct kmem_cac=
he *s, int cpu)
>                 deactivate_slab(s, slab, freelist);
>                 stat(s, CPUSLAB_FLUSH);
>         }
> -
> -       put_partials_cpu(s, c);
>  }
>
>  static inline void flush_this_cpu_slab(struct kmem_cache *s)
> @@ -4070,15 +3902,13 @@ static inline void flush_this_cpu_slab(struct kme=
m_cache *s)
>
>         if (c->slab)
>                 flush_slab(s, c);
> -
> -       put_partials(s);
>  }
>
>  static bool has_cpu_slab(int cpu, struct kmem_cache *s)
>  {
>         struct kmem_cache_cpu *c =3D per_cpu_ptr(s->cpu_slab, cpu);
>
> -       return c->slab || slub_percpu_partial(c);
> +       return c->slab;
>  }
>
>  static bool has_pcs_used(int cpu, struct kmem_cache *s)
> @@ -5646,13 +5476,6 @@ static void __slab_free(struct kmem_cache *s, stru=
ct slab *slab,
>                 return;
>         }
>
> -       /*
> -        * It is enough to test IS_ENABLED(CONFIG_SLUB_CPU_PARTIAL) below
> -        * instead of kmem_cache_has_cpu_partial(s), because kmem_cache_d=
ebug(s)
> -        * is the only other reason it can be false, and it is already ha=
ndled
> -        * above.
> -        */
> -
>         do {
>                 if (unlikely(n)) {
>                         spin_unlock_irqrestore(&n->list_lock, flags);
> @@ -5677,26 +5500,19 @@ static void __slab_free(struct kmem_cache *s, str=
uct slab *slab,
>                  * Unless it's frozen.
>                  */
>                 if ((!new.inuse || was_full) && !was_frozen) {
> +
> +                       n =3D get_node(s, slab_nid(slab));
>                         /*
> -                        * If slab becomes non-full and we have cpu parti=
al
> -                        * lists, we put it there unconditionally to avoi=
d
> -                        * taking the list_lock. Otherwise we need it.
> +                        * Speculatively acquire the list_lock.
> +                        * If the cmpxchg does not succeed then we may
> +                        * drop the list_lock without any processing.
> +                        *
> +                        * Otherwise the list_lock will synchronize with
> +                        * other processors updating the list of slabs.
>                          */
> -                       if (!(IS_ENABLED(CONFIG_SLUB_CPU_PARTIAL) && was_=
full)) {
> -
> -                               n =3D get_node(s, slab_nid(slab));
> -                               /*
> -                                * Speculatively acquire the list_lock.
> -                                * If the cmpxchg does not succeed then w=
e may
> -                                * drop the list_lock without any process=
ing.
> -                                *
> -                                * Otherwise the list_lock will synchroni=
ze with
> -                                * other processors updating the list of =
slabs.
> -                                */
> -                               spin_lock_irqsave(&n->list_lock, flags);
> -
> -                               on_node_partial =3D slab_test_node_partia=
l(slab);
> -                       }
> +                       spin_lock_irqsave(&n->list_lock, flags);
> +
> +                       on_node_partial =3D slab_test_node_partial(slab);
>                 }
>
>         } while (!slab_update_freelist(s, slab, &old, &new, "__slab_free"=
));
> @@ -5709,13 +5525,6 @@ static void __slab_free(struct kmem_cache *s, stru=
ct slab *slab,
>                          * activity can be necessary.
>                          */
>                         stat(s, FREE_FROZEN);
> -               } else if (IS_ENABLED(CONFIG_SLUB_CPU_PARTIAL) && was_ful=
l) {
> -                       /*
> -                        * If we started with a full slab then put it ont=
o the
> -                        * per cpu partial list.
> -                        */
> -                       put_cpu_partial(s, slab, 1);
> -                       stat(s, CPU_PARTIAL_FREE);
>                 }
>
>                 /*
> @@ -5744,10 +5553,9 @@ static void __slab_free(struct kmem_cache *s, stru=
ct slab *slab,
>
>         /*
>          * Objects left in the slab. If it was not on the partial list be=
fore
> -        * then add it. This can only happen when cache has no per cpu pa=
rtial
> -        * list otherwise we would have put it there.
> +        * then add it.
>          */
> -       if (!IS_ENABLED(CONFIG_SLUB_CPU_PARTIAL) && unlikely(was_full)) {
> +       if (unlikely(was_full)) {

This is not really related to your change but I wonder why we check
for was_full to detect that the slab was not on partial list instead
of checking !on_node_partial... They might be equivalent at this point
but it's still a bit confusing.

>                 add_partial(n, slab, DEACTIVATE_TO_TAIL);
>                 stat(s, FREE_ADD_PARTIAL);
>         }
> @@ -6396,8 +6204,8 @@ static __always_inline void do_slab_free(struct kme=
m_cache *s,
>                 if (unlikely(!allow_spin)) {
>                         /*
>                          * __slab_free() can locklessly cmpxchg16 into a =
slab,
> -                        * but then it might need to take spin_lock or lo=
cal_lock
> -                        * in put_cpu_partial() for further processing.
> +                        * but then it might need to take spin_lock
> +                        * for further processing.
>                          * Avoid the complexity and simply add to a defer=
red list.
>                          */
>                         defer_free(s, head);
> @@ -7707,39 +7515,6 @@ static int init_kmem_cache_nodes(struct kmem_cache=
 *s)
>         return 1;
>  }
>
> -static void set_cpu_partial(struct kmem_cache *s)
> -{
> -#ifdef CONFIG_SLUB_CPU_PARTIAL
> -       unsigned int nr_objects;
> -
> -       /*
> -        * cpu_partial determined the maximum number of objects kept in t=
he
> -        * per cpu partial lists of a processor.
> -        *
> -        * Per cpu partial lists mainly contain slabs that just have one
> -        * object freed. If they are used for allocation then they can be
> -        * filled up again with minimal effort. The slab will never hit t=
he
> -        * per node partial lists and therefore no locking will be requir=
ed.
> -        *
> -        * For backwards compatibility reasons, this is determined as num=
ber
> -        * of objects, even though we now limit maximum number of pages, =
see
> -        * slub_set_cpu_partial()
> -        */
> -       if (!kmem_cache_has_cpu_partial(s))
> -               nr_objects =3D 0;
> -       else if (s->size >=3D PAGE_SIZE)
> -               nr_objects =3D 6;
> -       else if (s->size >=3D 1024)
> -               nr_objects =3D 24;
> -       else if (s->size >=3D 256)
> -               nr_objects =3D 52;
> -       else
> -               nr_objects =3D 120;
> -
> -       slub_set_cpu_partial(s, nr_objects);
> -#endif
> -}
> -
>  static unsigned int calculate_sheaf_capacity(struct kmem_cache *s,
>                                              struct kmem_cache_args *args=
)
>
> @@ -8595,8 +8370,6 @@ int do_kmem_cache_create(struct kmem_cache *s, cons=
t char *name,
>         s->min_partial =3D min_t(unsigned long, MAX_PARTIAL, ilog2(s->siz=
e) / 2);
>         s->min_partial =3D max_t(unsigned long, MIN_PARTIAL, s->min_parti=
al);
>
> -       set_cpu_partial(s);
> -
>         s->cpu_sheaves =3D alloc_percpu(struct slub_percpu_sheaves);
>         if (!s->cpu_sheaves) {
>                 err =3D -ENOMEM;
> @@ -8960,20 +8733,6 @@ static ssize_t show_slab_objects(struct kmem_cache=
 *s,
>                         total +=3D x;
>                         nodes[node] +=3D x;
>
> -#ifdef CONFIG_SLUB_CPU_PARTIAL
> -                       slab =3D slub_percpu_partial_read_once(c);
> -                       if (slab) {
> -                               node =3D slab_nid(slab);
> -                               if (flags & SO_TOTAL)
> -                                       WARN_ON_ONCE(1);
> -                               else if (flags & SO_OBJECTS)
> -                                       WARN_ON_ONCE(1);
> -                               else
> -                                       x =3D data_race(slab->slabs);
> -                               total +=3D x;
> -                               nodes[node] +=3D x;
> -                       }
> -#endif
>                 }
>         }
>
> @@ -9108,12 +8867,7 @@ SLAB_ATTR(min_partial);
>
>  static ssize_t cpu_partial_show(struct kmem_cache *s, char *buf)
>  {
> -       unsigned int nr_partial =3D 0;
> -#ifdef CONFIG_SLUB_CPU_PARTIAL
> -       nr_partial =3D s->cpu_partial;
> -#endif
> -
> -       return sysfs_emit(buf, "%u\n", nr_partial);
> +       return sysfs_emit(buf, "0\n");
>  }
>
>  static ssize_t cpu_partial_store(struct kmem_cache *s, const char *buf,
> @@ -9125,11 +8879,9 @@ static ssize_t cpu_partial_store(struct kmem_cache=
 *s, const char *buf,
>         err =3D kstrtouint(buf, 10, &objects);
>         if (err)
>                 return err;
> -       if (objects && !kmem_cache_has_cpu_partial(s))
> +       if (objects)
>                 return -EINVAL;
>
> -       slub_set_cpu_partial(s, objects);
> -       flush_all(s);
>         return length;
>  }
>  SLAB_ATTR(cpu_partial);
> @@ -9168,42 +8920,7 @@ SLAB_ATTR_RO(objects_partial);
>
>  static ssize_t slabs_cpu_partial_show(struct kmem_cache *s, char *buf)
>  {
> -       int objects =3D 0;
> -       int slabs =3D 0;
> -       int cpu __maybe_unused;
> -       int len =3D 0;
> -
> -#ifdef CONFIG_SLUB_CPU_PARTIAL
> -       for_each_online_cpu(cpu) {
> -               struct slab *slab;
> -
> -               slab =3D slub_percpu_partial(per_cpu_ptr(s->cpu_slab, cpu=
));
> -
> -               if (slab)
> -                       slabs +=3D data_race(slab->slabs);
> -       }
> -#endif
> -
> -       /* Approximate half-full slabs, see slub_set_cpu_partial() */
> -       objects =3D (slabs * oo_objects(s->oo)) / 2;
> -       len +=3D sysfs_emit_at(buf, len, "%d(%d)", objects, slabs);
> -
> -#ifdef CONFIG_SLUB_CPU_PARTIAL
> -       for_each_online_cpu(cpu) {
> -               struct slab *slab;
> -
> -               slab =3D slub_percpu_partial(per_cpu_ptr(s->cpu_slab, cpu=
));
> -               if (slab) {
> -                       slabs =3D data_race(slab->slabs);
> -                       objects =3D (slabs * oo_objects(s->oo)) / 2;
> -                       len +=3D sysfs_emit_at(buf, len, " C%d=3D%d(%d)",
> -                                            cpu, objects, slabs);
> -               }
> -       }
> -#endif
> -       len +=3D sysfs_emit_at(buf, len, "\n");
> -
> -       return len;
> +       return sysfs_emit(buf, "0(0)\n");
>  }
>  SLAB_ATTR_RO(slabs_cpu_partial);
>
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
AJuCfpHaSg2O0vZhfAD%2B61i7Vq%3DT3OeQ%3DNXirXMd-2GCKRAgjg%40mail.gmail.com.

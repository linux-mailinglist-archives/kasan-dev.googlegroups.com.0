Return-Path: <kasan-dev+bncBCAJFDXE4QGBBJ7IUK2QMGQENHBQB3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id CE779940DD8
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Jul 2024 11:36:41 +0200 (CEST)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-260fd501151sf4884612fac.3
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jul 2024 02:36:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722332200; cv=pass;
        d=google.com; s=arc-20160816;
        b=ekU8bzS/OFhnj5wlyTqQ4HLkVaA0Er9zKxEHYM10VS8YAiTYreZv2PPvSRXg++pWcu
         ldHTvUwlB0+uOfG9T2FmMYT3l3gxYU6mjRWQ3M7d2Kts5gmWNa3HNlj8awRgdgxd4EzR
         puRcEertV7rWnZo27SBWwniqbdgCUHk6PPOOdp/+B39jgvlvARjy4CorIBSokQ/gAIFP
         E0XvILd32lAO3hwq0+DkLF/9HrYbnh3uVRRGwGYcEyGKsdCAHn7XGsWbTQH8mtH4PlMc
         mSSvH70xr3eTC5ZxqDB2+dBKfdPP8SfRjBnrKaqAJHK6YBWuQaFbnFqYQzr7TzMpZRMM
         v5vg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=JyH5t2XEWBywnj47X37Vgw1d/GYaFwFkKKBONwlqn5s=;
        fh=QTc7+7FD2BWXp9IEQBZUWC+W0rHNZ3e1keVaGV1+y1w=;
        b=FTdC9zs3E5Z+oom+C6W8CEXceojr0eV9/UVxjcVAliEkfSr2Apbt3W+R2Z6hQbKbaV
         ZM18sXVP4Pilklppy6gXQfZQ+LmuSc5BvlDLvSbHwRpn8nQaylMVemrHvd/QoXtm5SAL
         U41W5F4OoIfQXz2gMMJmMlL7WgF1jgB4SCncaEDsOzsrkGZHvPkhL/nTAWBw6K+uwI8A
         JJrjz6ncX1b4Gqe+MRFxffWLxENvbOpzU6E+pE/kIUvpNiHTEaeRaedjmnk3FHIEziBo
         n4z3qTfB6IbSHeT16FEzIvSDYi0S7TnBIGrSpE7JdXGP6/yFxJRcrHUjkTl6qE8RgPwa
         wd9A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=GOBK9U+q;
       spf=pass (google.com: domain of adrianhuang0701@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=adrianhuang0701@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722332200; x=1722937000; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JyH5t2XEWBywnj47X37Vgw1d/GYaFwFkKKBONwlqn5s=;
        b=QGjCa2Wl2GfaqaxNWEPxnCJFz7Ij3YUIS3DzYPzUsxH0+5YjcjcXZCO/7j8GhquO9t
         Kqrd4InTvIximtUc/jlvEUfr/pBNtJ/HJEwcTXCoVPF2om/wK8Lg1uXWY/YbSQL/WLHb
         zIuZNX4flyr+iv1YfaDT+4mQr7IZz2X3WKZnjPa4KLVRBQFXoZE0ithdF5I7EA0Az1YW
         oR9uOMV2A3j0eVKb1B/gA+K3l1x6VH0PIV3yj59X5mNGW6QEBXdWxE4cjIjvzuyjwoP1
         MGMYSCi/EJXopM8rUQoYXAAR0iTkuB0uxwC6f4yi2E53/CKsY+CDQ/8PykCQ3vD9S5Sh
         uS/Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1722332200; x=1722937000; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=JyH5t2XEWBywnj47X37Vgw1d/GYaFwFkKKBONwlqn5s=;
        b=bWwhLKIZOz+C7+bcuAQylxCLyfWiBWP1dbwmOXMzHYpABNuj108ob8gzDlcxa+iYsy
         vYL6+5bKnxssjYhjeP50IbojbYBN38uRr4z97zBLQQSsYxxLx7s8N5W1XEVYTp6tAfMQ
         BOpl/6sIr1JGa/PFNYlav6KagouAK6Xy7zPRoUp/tHveUuhJ2WAEA5JCwMdDxQKwMcH4
         43ONLcMIR8PTNX/Mr/VUxg1Iy/G5GIEX4y6EUmKQpHzYhajMh9nK3q866IfJbxRJJQ0E
         x/1IGY45P7F37JSNJsfO3p1GQvvk5ky/o1Uo1a0vVcoAjbjFAVMn3GvIY/vLgSWPkSzA
         pTaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722332200; x=1722937000;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=JyH5t2XEWBywnj47X37Vgw1d/GYaFwFkKKBONwlqn5s=;
        b=ioZifzexSaBYtKdzUcLcVd+CXbnOr0W2jSRB9qxBiRQMvNAq++Yzo1jpYokU2V4ILI
         uMlfOSfpxEZiENHJ1Ue+hQ8rDpoRkFPs43+bdyLtsC/Mb9UorSYmj3vMJHhrIsEIzwqj
         k+lE2/X98oMwaED2Dh/HTWDBmJvyQEXiaD0dzUQtiLDuUvTTwr1HDG0TwZcgcSGWiPh/
         CWktWiddkFYyjLb/HyE1h8UPwprmnmm9xhIAo0ZjjV0jD20eHC2ONGKNTUq8A0eTviJ2
         9eeO0jX/p9YT7jv7lviL+1rXUxiTl6euFwEdBUv1w3IK/PQqeWmliQPpIUUatI3zGKQb
         6ihg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXBFn7nj8w9g8QwKdalaFGaDn9PJa6CK2KAt/comgnaygzO7mzkqMHZZjxLYJEjAgeGKMKN7lAJVXK6EalXfzG/z2QmCRwTdg==
X-Gm-Message-State: AOJu0Yw0b1SQLoCwdOK5BV1eslqkouI1YIZU9Z6h5SuJrssW0gxFp+wd
	TvwHfr9GEfS8FPtUkaIe6235bkAl1cuSvJzWvTnN2ZZoQFwZUfDm
X-Google-Smtp-Source: AGHT+IGaAR5LL/g9Xu5hevCxtNt0yk307bICzB+wdsZgYPDAlpRzFMw/vWlROlrtEEl3pOoK642tCg==
X-Received: by 2002:a05:6870:506:b0:261:c65e:919f with SMTP id 586e51a60fabf-267d4dcabf7mr13493160fac.21.1722332200227;
        Tue, 30 Jul 2024 02:36:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:b52:b0:706:4227:a6db with SMTP id
 d2e1a72fcca58-70ea9e2ef36ls3355523b3a.2.-pod-prod-04-us; Tue, 30 Jul 2024
 02:36:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVRgW0vxEFbTgzNk55LN6676HbbGWha1+n9sL6mJ5iDC8S/OojTlNOzNR6Vny4k1y/z6QZW2sIP7D2mX1LVDdnLJwhmfR6h5MeafA==
X-Received: by 2002:a05:6a00:3d14:b0:708:11f:d153 with SMTP id d2e1a72fcca58-70ece931604mr8883857b3a.0.1722332198867;
        Tue, 30 Jul 2024 02:36:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722332198; cv=none;
        d=google.com; s=arc-20160816;
        b=BCROSLnaOy46Z1P06LKfN/pR6jLwae8QZPYLDvRiKNmh02mGSloEdocoaae2PoiRkF
         FTvFB60sBt40CppwYQNSyF0cB/wBmXSv/zjqf3ssqR94KusMS0FkmB7C2Kj6HcJsVWOz
         1F/33TEC2rPBjcWwWS6MT24DuP3ax//DSP/nA7D5KhFZKoJoAxlSvyphMq6RiRKpOiZs
         0+dZJgwDo7/iriZ5iGy2DlFCa0GmjuvZeCmq9AP+XtnlFeUvSbkL1Z37/3TAx0zha1jk
         F+IBKn8/l1aoix2AH2/hoEnyhkLfD2K4GovHju0DedKKmMEp9xkyQsYZRvAQRWAghfqd
         DgQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=C39pEMxxkaT6a0RlZ/9LBxSQHNmTTBvdXNRF5PK1T+8=;
        fh=ga5Alt5sqdMVfEMLq/+nd5bpqLkSzmBffrFrS4hyCjU=;
        b=e8Gqw+IgKmK1t70RWwuwBne5h7u5q/53ztosstyYBWx62l7x0UViTexmgiidI/+qRA
         NL7NLTBixWcavYOfvvpbyPaDWWhOuSbP463YG38yrDGnhIJHLmXgml1wcpnqEKs99+LC
         sW1y9BR8uucZV4AVH3zXhl65KBlFmYyFSKf+0vkw5E2BQERaGUccadPlSwQocFLsCzkv
         lvXf5MW/XvRQ4Bi+hlsf7rSWACvY8obCNGF6kAYOTcLCIDiQeKTmbdxvTeMuL88UmURB
         7J3y+Ho65MIOtrVcYBRvmGeHIUV5C5G238UxIoTV4OngLpz0e/ue+3ej6XK19o3TGh0T
         QXeg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=GOBK9U+q;
       spf=pass (google.com: domain of adrianhuang0701@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=adrianhuang0701@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x630.google.com (mail-pl1-x630.google.com. [2607:f8b0:4864:20::630])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-7aa1ba2bdb0si669051a12.5.2024.07.30.02.36.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Jul 2024 02:36:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of adrianhuang0701@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) client-ip=2607:f8b0:4864:20::630;
Received: by mail-pl1-x630.google.com with SMTP id d9443c01a7336-1fc60c3ead4so26596435ad.0
        for <kasan-dev@googlegroups.com>; Tue, 30 Jul 2024 02:36:38 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWHnUHc38Sa6xOOK0ipC7r/ETVAhIxS9FpTV6ki2kAzUbnbTgLgybuCY2QIj/MY2WbGEr39BaBHvusVTFCupxFrjGyNNQFO31QVGg==
X-Received: by 2002:a17:90a:2c44:b0:2cb:5654:8367 with SMTP id 98e67ed59e1d1-2cf7e5c1b45mr8578709a91.26.1722332198337;
        Tue, 30 Jul 2024 02:36:38 -0700 (PDT)
Received: from AHUANG12-3ZHH9X.lenovo.com (220-143-223-76.dynamic-ip.hinet.net. [220.143.223.76])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-2cdb73ddb7dsm12068860a91.24.2024.07.30.02.36.33
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 30 Jul 2024 02:36:37 -0700 (PDT)
From: Adrian Huang <adrianhuang0701@gmail.com>
To: urezki@gmail.com
Cc: adrianhuang0701@gmail.com,
	ahuang12@lenovo.com,
	akpm@linux-foundation.org,
	andreyknvl@gmail.com,
	bhe@redhat.com,
	dvyukov@google.com,
	glider@google.com,
	hch@infradead.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	ryabinin.a.a@gmail.com,
	sunjw10@lenovo.com,
	vincenzo.frascino@arm.com
Subject: Re: [PATCH 1/1] mm/vmalloc: Combine all TLB flush operations of KASAN shadow virtual address into one operation
Date: Tue, 30 Jul 2024 17:36:30 +0800
Message-Id: <20240730093630.5603-1-ahuang12@lenovo.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <Zqd9AsI5tWH7AukU@pc636>
References: <Zqd9AsI5tWH7AukU@pc636>
MIME-Version: 1.0
X-Original-Sender: AdrianHuang0701@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=GOBK9U+q;       spf=pass
 (google.com: domain of adrianhuang0701@gmail.com designates
 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=adrianhuang0701@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
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

On Mon, Jul 29, 2024 at 7:29 PM Uladzislau Rezki <urezki@gmail.com> wrote:
> It would be really good if Adrian could run the "compiling workload" on
> his big system and post the statistics here.
>
> For example:
>   a) v6.11-rc1 + KASAN.
>   b) v6.11-rc1 + KASAN + patch.

Sure, please see the statistics below.

Test Result (based on 6.11-rc1)
===============================

1. Profile purge_vmap_node()

   A. Command: trace-cmd record -p function_graph -l purge_vmap_node make -j $(nproc)

   B. Average execution time of purge_vmap_node():

	no patch (us)		patched (us)	saved
	-------------		------------    -----
      	 147885.02	 	  3692.51	 97%  

   C. Total execution time of purge_vmap_node():

	no patch (us)		patched (us)	saved
	-------------		------------	-----
	  194173036		  5114138	 97%

   [ftrace log] Without patch: https://gist.github.com/AdrianHuang/a5bec861f67434e1024bbf43cea85959
   [ftrace log] With patch: https://gist.github.com/AdrianHuang/a200215955ee377288377425dbaa04e3

2. Use `time` utility to measure execution time
 
   A. Command: make clean && time make -j $(nproc)

   B. The following result is the average kernel execution time of five-time
      measurements. ('sys' field of `time` output):

	no patch (seconds)	patched (seconds)	saved
	------------------	----------------	-----
	    36932.904		   31403.478		 15%

   [`time` log] Without patch: https://gist.github.com/AdrianHuang/987b20fd0bd2bb616b3524aa6ee43112
   [`time` log] With patch: https://gist.github.com/AdrianHuang/da2ea4e6aa0b4dcc207b4e40b202f694

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240730093630.5603-1-ahuang12%40lenovo.com.

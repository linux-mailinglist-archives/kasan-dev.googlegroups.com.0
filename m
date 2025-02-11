Return-Path: <kasan-dev+bncBD22BAF5REGBBGWYV26QMGQEHLRACMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id EAE41A3163F
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2025 20:59:23 +0100 (CET)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-471939c23b6sf65562931cf.2
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2025 11:59:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739303962; cv=pass;
        d=google.com; s=arc-20240605;
        b=jP4nihSn134+B3bG83Jw41pn1o4dmnbRbhOgeuIOp3A35ytoQAasMTSkTvJcSpGjPb
         yDPOZVLaAj5g/2Isny8pjVdI3orM+ufhUnVNa7izN4rJiVUaJMpMGYS4MJzXKpocfvP0
         2HSEEqFhfyH93h62iQ0rfzyRS0wsHjt/US/wAxJGoPjECwC5prkm0c+5iwg6vIzRqgno
         Udd4MwkZez1rgSZlDWiapuhRRQvlE4MXZaOSQBcJpYhcAKZQE4upIWpR5ASSaD9QiSP2
         qhHOI/VD/tBYHKcpxDOKz70zJF93b8KyrH8Ik1h1hAnR33p9qJpjezUZESWVLQ86gvZD
         OZTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=XVlPlPZg1c985wU8ghQkv1xfuuSyhxKHr3MknXU2MFo=;
        fh=R+32E+xWbYZOXM+OiBVJ6eCxHV5B3zcias3nCQZg7LY=;
        b=cDfggO9Atjhcj9Or0xBITRI4PJvDfDU5Ko7RaQzvYbge2c25H/7dZwRmPEjW7BaUI8
         o5SN5M08/F13ozGCudYZ0TRoWOfEhJ9bLjtSM2ZWBPTj4vXBNe/CzBiSJ6uA6vnlk6mJ
         IR+TaQQySSUKBU2+UbMrZ9kiG2P9pnTIJ6Eg/Mh+ZhWGAek2z++E/5174YiZRtRhPKp+
         EagOWKBTd1qfMNfuJYmMIQSxd9w4i2GxT+PonJf50rDDsQXPF1a5X7o5P8q+0r3jktwK
         JjZp50tBI725kkLdxv7325KwSRfY9VhEQ14yrC6V9ajk0A72rkOb3nJklRTy/6FvSVD5
         Ox2Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=kV4Cnzcg;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.13 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739303962; x=1739908762; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=XVlPlPZg1c985wU8ghQkv1xfuuSyhxKHr3MknXU2MFo=;
        b=Vv7NxWk8wsffBiJ6JuMCcKWxUg6iAeriWfnSYGGnboCOvQXtSaV/F+9/rPen75C5Ie
         5Nf+IOu3GmoMc66n1vbUKhsvKhiYlrsuN65PmnIqftGtOym9z5CpMpODVslL0fpXbnF/
         623bubkTWMof097uCdAibx6YtVyG6GKgwrwX421ZFIbllYPJVSJJsjbxn6lZJAqtprfG
         KchbBXROSwCSl/6Bm/wxMmhWTzLGnmnhbEM7kNW8ehJHyZKGqLSjGuU7jpDlxZSzNC94
         jS3LWYmig6gHUJVocNPPZtn0t9L5VLrDmQPzlnZFclgU6N7jUhq4S1aumWi5dxhczL4Z
         hF/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739303962; x=1739908762;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=XVlPlPZg1c985wU8ghQkv1xfuuSyhxKHr3MknXU2MFo=;
        b=DFi8CaLh5BA1a58VHoi5EUkIdDmU92kpqVTAPbmGXgJRqmbgm7l9pQnsJkd6bZ8HPD
         EfddWeldAeFny0r3IQjm9dtbH0e/iFik/xJfz+i/VIRoaw3gn+wKXejYGjKOedewA/W0
         Bzuhgtxs60yI+TflsJ8wXjdMmqY0isZK+lnRJXh5KUrbmp8SJGOlCX1dY2HYB1SjEDnM
         lNUikGzsHBMCq+p4klSLTCIy2+WpCabN7pwWIV7kfhUIfavy6kRlfBLYD+zo8a4eNZR7
         8BippK0eAAsFoT5RPIbObpTDzTh1+4q8/BT7lYHA0BDRpe3jkDHokRjqKPxEUxVFhibB
         ncZQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVkTlqsKoazw1r11ZG42Kk/D73U7ltoKqIA1IvlKWR7w7FG7ohhGXUzqUND6RnW5Br+ORYGTA==@lfdr.de
X-Gm-Message-State: AOJu0YzVHlzp+HEjgRAt55Vc5QoIqKhmfzBFBNPrWWXwR3Ujan5AqtaS
	4B3gO6cp69qfi7bzGDBeDXon+iD1JiTJRGWvaxcmOBWxJJZ0FcUQ
X-Google-Smtp-Source: AGHT+IGpduAcfHBRIQslbVwJMPKkS8NJ0dWo9nZZ0mpTobSVurzAqvV0BTDN+2D+LpRTXCJmBB7DTg==
X-Received: by 2002:a05:622a:652:b0:471:89e5:515b with SMTP id d75a77b69052e-471afe57c31mr5176561cf.24.1739303962509;
        Tue, 11 Feb 2025 11:59:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVEspupxI4DT8sbiE1uvZhyF/wlRsgj6VaMUDKfCrBa88w==
Received: by 2002:ac8:498d:0:b0:466:8f66:abeb with SMTP id d75a77b69052e-471af46489els3614241cf.1.-pod-prod-09-us;
 Tue, 11 Feb 2025 11:59:21 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWvxxqdh5VKhL2oHYWVF+mjKxeVbCGadm53LzU3gDlzFqYNHqTitiNjvTyedcF+jQJ6+Duk2E+K6NU=@googlegroups.com
X-Received: by 2002:a05:622a:13c6:b0:471:a71c:eac6 with SMTP id d75a77b69052e-471afee062emr6167451cf.35.1739303961595;
        Tue, 11 Feb 2025 11:59:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739303961; cv=none;
        d=google.com; s=arc-20240605;
        b=XktaRsC3eKI8fqZQrrsQ1bOU751tKTHEL6RhkiEi0MKCRJ+mNg0QujQl+opx1tvTui
         ZYR/P99v7lZX04eYk54c4I+mW7xnqtoOkfTeg3v5WdQZfpk6r6b0t9IFJePwBZ66Pies
         FjYcVj0x0wlYJenzjpyAje5j3ha4W1xaJf0FVjfgEFbOuCEW6PCfH84Q0Q5M7eHBqDcU
         ceCy6xoo1fC9r09Oq8A85lMdhFSiHN7J4LnGWxYc8dzCl+kxMmMbrYV4MXfmYs2uhsUF
         FWOMX/jkeytWSgwp6kEjGEnh0aU1RF3wcORO0lbmKGFIOO5BIsUO08Fxwnf/v260buH1
         HIFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:content-language
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=BZe8LtLr9+krv/IduZBGXFiTl7ghurcrbRU6fbkTjAM=;
        fh=jN++NnhM6QHHw7OSCea5J3qRZfT7UUaD5FdvdIjnG80=;
        b=OJQbeZ/AU0axdD3yN2we8eLV/DuDhGEjtfO15j20lr9zTrDLt6eD3HFcNUpoGCN7U+
         Gjnefwhgw9SeVdeDHUB2O+mPtbZP1fjzeU+bFftRwuFG8EewZaQwE7zGo+SSKA4hRrZV
         n8JQUi1cuJEzHRrvFQmNsrcRb0TiFA93NstzuphNC2Flu/Chx3MfBP+DPBvnulYMUzBV
         oEvvQTQf/Y7yUlCHvXsU2MVJ/CY898Uv2HKrY8fbLXs3EIdZFWvxELmMmu6ZHnu8N4Pf
         NrDHzXlMtY6ZHYGtc7GMW/zAbSiYuUkQUka5Qo2dwecYoGj1plWSUWiF5zGhI9SdW3nT
         d80A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=kV4Cnzcg;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.13 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.13])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-47140ed7620si5292241cf.0.2025.02.11.11.59.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 11 Feb 2025 11:59:21 -0800 (PST)
Received-SPF: pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.13 as permitted sender) client-ip=192.198.163.13;
X-CSE-ConnectionGUID: L4DnG1g3QlGe10JfdbF66w==
X-CSE-MsgGUID: k0MnBqwhTviu4kCqlXlBsg==
X-IronPort-AV: E=McAfee;i="6700,10204,11342"; a="42786417"
X-IronPort-AV: E=Sophos;i="6.13,278,1732608000"; 
   d="scan'208";a="42786417"
Received: from fmviesa008.fm.intel.com ([10.60.135.148])
  by fmvoesa107.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 11 Feb 2025 11:59:20 -0800
X-CSE-ConnectionGUID: O9AWFUy3RJO+9tb/yFTjLQ==
X-CSE-MsgGUID: wP1KLtz+QiSuzJuh+2GpBA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.13,278,1732608000"; 
   d="scan'208";a="112826024"
Received: from msatwood-mobl.amr.corp.intel.com (HELO [10.125.108.48]) ([10.125.108.48])
  by fmviesa008-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 11 Feb 2025 11:59:16 -0800
Message-ID: <3d750b58-d911-4f24-93e4-b84213849071@intel.com>
Date: Tue, 11 Feb 2025 11:59:15 -0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 08/15] x86: Physical address comparisons in fill_p*d/pte
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: luto@kernel.org, xin@zytor.com, kirill.shutemov@linux.intel.com,
 palmer@dabbelt.com, tj@kernel.org, andreyknvl@gmail.com, brgerst@gmail.com,
 ardb@kernel.org, dave.hansen@linux.intel.com, jgross@suse.com,
 will@kernel.org, akpm@linux-foundation.org, arnd@arndb.de, corbet@lwn.net,
 dvyukov@google.com, richard.weiyang@gmail.com, ytcoode@gmail.com,
 tglx@linutronix.de, hpa@zytor.com, seanjc@google.com,
 paul.walmsley@sifive.com, aou@eecs.berkeley.edu, justinstitt@google.com,
 jason.andryuk@amd.com, glider@google.com, ubizjak@gmail.com,
 jannh@google.com, bhe@redhat.com, vincenzo.frascino@arm.com,
 rafael.j.wysocki@intel.com, ndesaulniers@google.com, mingo@redhat.com,
 catalin.marinas@arm.com, junichi.nomura@nec.com, nathan@kernel.org,
 ryabinin.a.a@gmail.com, dennis@kernel.org, bp@alien8.de,
 kevinloughlin@google.com, morbo@google.com, dan.j.williams@intel.com,
 julian.stecklina@cyberus-technology.de, peterz@infradead.org, cl@linux.com,
 kees@kernel.org, kasan-dev@googlegroups.com, x86@kernel.org,
 linux-arm-kernel@lists.infradead.org, linux-riscv@lists.infradead.org,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev,
 linux-doc@vger.kernel.org
References: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
 <2c2a71ec844db597f30754dd79faf87c9de0b21f.1738686764.git.maciej.wieczor-retman@intel.com>
 <c344dfaa-7e79-498f-89d7-44631140d0f4@intel.com>
 <lm5dg55q4vhhlsbsrvtskpz2hhdxa25pieq4gmf62ogtr4b4tw@xsq7ua7i5lto>
From: Dave Hansen <dave.hansen@intel.com>
Content-Language: en-US
Autocrypt: addr=dave.hansen@intel.com; keydata=
 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
In-Reply-To: <lm5dg55q4vhhlsbsrvtskpz2hhdxa25pieq4gmf62ogtr4b4tw@xsq7ua7i5lto>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dave.hansen@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=kV4Cnzcg;       spf=pass
 (google.com: domain of dave.hansen@intel.com designates 192.198.163.13 as
 permitted sender) smtp.mailfrom=dave.hansen@intel.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On 2/7/25 08:37, Maciej Wieczor-Retman wrote:
> @@ -287,7 +290,7 @@ static pte_t *fill_pte(pmd_t *pmd, unsigned long vaddr)
>  	if (pmd_none(*pmd)) {
>  		pte_t *pte = (pte_t *) spp_getpage();
>  		pmd_populate_kernel(&init_mm, pmd, pte);
> -		if (pte != pte_offset_kernel(pmd, 0))
> +		if (__pa(pte) != (pmd_val(*pmd) & pmd_pfn_mask(*pmd)))
>  			printk(KERN_ERR "PAGETABLE BUG #03!\n");
>  	}
>  	return pte_offset_kernel(pmd, vaddr);

Open coding it like this is fine with me.  The p*_offset_kernel(p*,0)
thing is arguably even harder to parse.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3d750b58-d911-4f24-93e4-b84213849071%40intel.com.

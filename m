Return-Path: <kasan-dev+bncBDZMFEH3WYFBBA6YYXGAMGQEBJIXRYI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id +XAzBAZskWk5igEAu9opvQ
	(envelope-from <kasan-dev+bncBDZMFEH3WYFBBA6YYXGAMGQEBJIXRYI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Sun, 15 Feb 2026 07:47:34 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9387A13E252
	for <lists+kasan-dev@lfdr.de>; Sun, 15 Feb 2026 07:47:33 +0100 (CET)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-2a7d7b87977sf26244915ad.0
        for <lists+kasan-dev@lfdr.de>; Sat, 14 Feb 2026 22:47:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1771138051; cv=pass;
        d=google.com; s=arc-20240605;
        b=aGx4trvnwBfj2xG4PoJdCDUpa36SWd/0bubfyHeTjyv7K+hPVNIK1ipfq9iiNTrwVS
         IgM7Jr5uGYUALXY3r83YxYk4REhIPXQR5n4HQkskntISmAJgT/Lm7o2Y69WpDKP0x+bQ
         eZQd4kO9vUXYDvptYUH1g0i65m2MUSODZO19bDKdIzzG8QH3f/v9PJfNaWdyGusxhI3f
         gEdSafIgcLYPPZ18Re1zwldy6lsSCG8P7AAvgCZ2Tn/J86lVwYEN4sjdoq7KmUknCQ/8
         cP0GgKg4/BfW92HTISN+GQ2h/Q17qx9miejUqeildOI/OH+GGpnqsGm72OdnS8BaivgD
         tq4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=44AHUDe+rTHIG2vBbLjPJ31M3O7+SY2+OWUVO0e7hXA=;
        fh=8hEg6GycQwB0bS3fSjWDyrrLoWcSgPOLYfq1l+GPnQc=;
        b=UZ085NHhjjUK0cpkdtgsqP25LA4gT75ZD3vOFRuqKO0u8e0n09BdPDwUs7kyAfTwFA
         v3RsD9w8rSb+ZJIhhbqEjcEnJRrx9n2Ykq5SZ2lQWA8mYUSj79s1bTd848udYdNeWWPh
         ipwz21BZbpJdhXUB1NUf1edWnTJ0+C6IcvxrOexTJFMp2Yu6FzkiVDp3VY7BtuBRhdwY
         ptaHpVQPof5dotInEucqbgLIRghRiWgQJpQGrbSc/zqUcC8DtGi4KbofU8m2vsVA5JQ6
         nLvVO7fRjRk2Vu4CMlt2pdga3D1N6FC8AMmLWIICozi0wh16bxAwbf71hw1YeqoQHj0V
         yXxQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Pd5ZgntW;
       spf=pass (google.com: domain of rppt@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1771138051; x=1771742851; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=44AHUDe+rTHIG2vBbLjPJ31M3O7+SY2+OWUVO0e7hXA=;
        b=i3ldLwlzYC1EAMxpxp6bhINBJr02PXgDDboc3fnCdWrBqVH6hmi2MS1p2NXfw4FlIm
         5vW25NIsCEx9n9MUc57Lyuf/OB6mo7lH8n0DTXd/pghRWdkkymanjnYfuJ0mz6eLk0TT
         CsKq+cV8+Rr3rDbXuuSr7dqPZ6LvHfOC7L8kR6x57U3AlYSgy/Nl+1wTcAhbar96yS0b
         pk/WlNhZl8bA150AS2SKVFOWHXsbFI7RF3RMaNgSo/rak5xM04DK1lRvSvw7dzxcl5Qc
         tlzC8bho2pqhkjnAjM11iTVQ+yBl7dErESZyvxrq5ieo3n5NxCWhvNmzSjWPgJj/jezP
         JLbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1771138051; x=1771742851;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=44AHUDe+rTHIG2vBbLjPJ31M3O7+SY2+OWUVO0e7hXA=;
        b=bDxlK0S4iFtbCO+pw00GcOFhjdL+raZCIU3ViTfv2E+S7tb2ahVH8s3xJsi9HnIt/P
         6lexMO+0EGjzs4LTEwAOtIDi8ifGxyXSJ4PV/IF8AtwhrfPda9TU40n41pmbh6UAz6C7
         xeWfYPd0hQyAKMX/90f7ENvrSB5BXjNYR7DGyORfQnLg3dc0Bm5YU2P0S0m1Bn9JBwfs
         NpFlXnNSaAC0T3ktp1p6PdbHZHAG1S+BnNnYz2MxZfEGc4sLZcOJWXHfaJj/NWtfOC0+
         DHHSIgRc1LdYxc8iTiWn47gU/J/ICgDxCCR0X2bvwpqaia1jhQeTljqvuvPZJE4u0Jaz
         J8gg==
X-Forwarded-Encrypted: i=2; AJvYcCW2mF8YBC3t4TGp+8/uUtDF1/sHKNxPFqK+J7WngesXlx9brPbPE6QZxwv6laziF4bRnMHXEw==@lfdr.de
X-Gm-Message-State: AOJu0YySx65FSrqnkblH2OU1UvEBc4A+nuVD90FrYlTalknj1DEfmdDD
	BRQkV9QKzboRc/5alz1FRniBu2e3C8gX4VEzahL98MkXSppw389BIUNm
X-Received: by 2002:a17:902:e787:b0:2a7:d5c0:c659 with SMTP id d9443c01a7336-2ab50519bc0mr74543955ad.5.1771138051532;
        Sat, 14 Feb 2026 22:47:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HSIDwOWdLpxA8iJ1a2mP/XkTnYFOEi0sAvlnAkTEV8TA=="
Received: by 2002:a17:902:ea11:b0:298:e5:d986 with SMTP id d9443c01a7336-2ab3c3f9143ls34280385ad.1.-pod-prod-09-us;
 Sat, 14 Feb 2026 22:47:30 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUsI7JmD1GTKXucDUVUj2G30uqsaVy3Alf2snmU7kvdI7mGpC3auSonS7hWN/dimx7mumrUy9fFBlU=@googlegroups.com
X-Received: by 2002:a17:903:1b43:b0:2a0:9fc8:a98b with SMTP id d9443c01a7336-2ab505d91ccmr83393895ad.40.1771138049993;
        Sat, 14 Feb 2026 22:47:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1771138049; cv=none;
        d=google.com; s=arc-20240605;
        b=TDzwXOu5pBdFVM/6Wgxrr4s36yKJdfWRQmwu3mA97chYZol8T86ceO7gBT1vFaTIXn
         0FE7bTuYn8sEJpahEKO4slA2nyK+L9TLZtWfFgZnx+F3xD+3B3eLwykTmSgTmaxl/25e
         vsl/z+19kfoHe4wXFKFKZRobbCo5Y00S3lCvcZghZg2nCTAcPn8Lm1z2+GNnIBlYF4Nb
         PXhYbDUgJ6Q62kDFZZj2WNAiWGuDSmfLwdWBO3tDfzDaLjOfAzqRk3V6+BhU/C2i6y6P
         tfoa7ikEuKeIcbrez590q0mA/4SBZhtZfz5ShU8u+BE/81bL2kHq6FFXI9N9iyC1/b8d
         an8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=2l7h6AZgsCQNAFoeKxysvqrlTHtQeTpw/FXQJGzkYTE=;
        fh=3K5G+2I2gZaB4H7qqn8bfxZvzbU2bhaDvYsW0jh490E=;
        b=KhuV2q3ukRmZCwDhVemPauYOlY4i5rYGP4xIxxTeH0OW/ddukowW7fZbC7rYKYvLcS
         Hb+WwdwaZtDLXlv15wn3a0FlBnmeNxhGVICIk6GjCNmAkfc1+HSlTodD6rLNodYkW+d5
         YzMo9QSN+g/vD/oH+T41x2vpDRk58PBXUMGU0axRsuNWXzQ8D2i1aMfJ82XlIFWL0ocF
         mlEvhZfWq1Iq/mk+lKJ/ehiX+fVNzpTkKLZpWRKK+pfMLsV1dWhp9NgcY60+PpBOlByA
         IC10ti794OgRIz6MCNcGpVqRzbnZEvDcpEmI25XaJ956IY1o1cw+sxJbyrKxpXZVmAIk
         0kZQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Pd5ZgntW;
       spf=pass (google.com: domain of rppt@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2ad1a725ecbsi1500195ad.1.2026.02.14.22.47.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 14 Feb 2026 22:47:29 -0800 (PST)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id DB86D6001D;
	Sun, 15 Feb 2026 06:47:28 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E93C7C4CEF7;
	Sun, 15 Feb 2026 06:47:25 +0000 (UTC)
Date: Sun, 15 Feb 2026 08:47:21 +0200
From: "'Mike Rapoport' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: Alexander Graf <graf@amazon.com>,
	Pasha Tatashin <pasha.tatashin@soleen.com>,
	Pratyush Yadav <pratyush@kernel.org>, kexec@lists.infradead.org,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH] kho: validate order in deserialize_bitmap()
Message-ID: <aZFr-TvaWn-KbA1u@kernel.org>
References: <20260214010013.3027519-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260214010013.3027519-1-elver@google.com>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Pd5ZgntW;       spf=pass
 (google.com: domain of rppt@kernel.org designates 172.105.4.254 as permitted
 sender) smtp.mailfrom=rppt@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Mike Rapoport <rppt@kernel.org>
Reply-To: Mike Rapoport <rppt@kernel.org>
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
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	FROM_HAS_DN(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	TAGGED_FROM(0.00)[bncBDZMFEH3WYFBBA6YYXGAMGQEBJIXRYI];
	RCVD_TLS_LAST(0.00)[];
	MIME_TRACE(0.00)[0:+];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	TO_DN_SOME(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	MISSING_XM_UA(0.00)[];
	HAS_REPLYTO(0.00)[rppt@kernel.org];
	RCVD_COUNT_FIVE(0.00)[5];
	FROM_EQ_ENVFROM(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCPT_COUNT_SEVEN(0.00)[8];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail-pl1-x63c.google.com:helo,mail-pl1-x63c.google.com:rdns,googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: 9387A13E252
X-Rspamd-Action: no action

Hi Marco,

On Sat, Feb 14, 2026 at 01:57:51AM +0100, Marco Elver wrote:
> The function deserialize_bitmap() calculates the reservation size using:
> 
>     int sz = 1 << (order + PAGE_SHIFT);
> 
> If a corrupted KHO image provides an order >= 20 (on systems with 4KB
> pages), the shift amount becomes >= 32, which overflows the 32-bit
> integer. This results in a zero-size memory reservation.
> 
> Furthermore, the physical address calculation:
> 
>     phys_addr_t phys = elm->phys_start + (bit << (order + PAGE_SHIFT));
> 
> can also overflow and wrap around if the order is large. This allows a
> corrupt KHO image to cause out-of-bounds updates to page->private of
> arbitrary physical pages during early boot.
> 
> Fix this by adding a bounds check for the order field.
> 
> Fixes: fc33e4b44b27 ("kexec: enable KHO support for memory preservation")
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  kernel/liveupdate/kexec_handover.c | 5 +++++
>  1 file changed, 5 insertions(+)
> 
> diff --git a/kernel/liveupdate/kexec_handover.c b/kernel/liveupdate/kexec_handover.c
> index b851b09a8e99..ec353e4b68a6 100644
> --- a/kernel/liveupdate/kexec_handover.c
> +++ b/kernel/liveupdate/kexec_handover.c
> @@ -463,6 +463,11 @@ static void __init deserialize_bitmap(unsigned int order,
>  	struct kho_mem_phys_bits *bitmap = KHOSER_LOAD_PTR(elm->bitmap);
>  	unsigned long bit;
>  
> +	if (order > MAX_PAGE_ORDER) {

Preserved order can be larger than MAX_PAGE_ORDER. 
Let's make 'sz' unsigned long and add checks that calculations won't
overflow.

> +		pr_warn("invalid order %u for preserved bitmap\n", order);
> +		return;
> +	}
> +
>  	for_each_set_bit(bit, bitmap->preserve, PRESERVE_BITS) {
>  		int sz = 1 << (order + PAGE_SHIFT);
>  		phys_addr_t phys =
> -- 
> 2.53.0.335.g19a08e0c02-goog

-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aZFr-TvaWn-KbA1u%40kernel.org.

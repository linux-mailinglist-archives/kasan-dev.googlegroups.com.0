Return-Path: <kasan-dev+bncBCUO3AHUWUIRBNMK7LDAMGQEWBWU3WI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id DC7BFBB41CD
	for <lists+kasan-dev@lfdr.de>; Thu, 02 Oct 2025 15:59:18 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-4df80d0d4aasf42611461cf.2
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Oct 2025 06:59:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759413557; cv=pass;
        d=google.com; s=arc-20240605;
        b=h/2soyFGK7MOGLlJJxuMFbxbcvvdu/YaEiJ3yq9/sizSeb21Lcg3fjPD+UdM6DlDPQ
         eUH2OseCgCFIEIgxMTCmoUHvscig0BH65t8HRk7+Jv4IE3Tp1ObXhPpDbQeY8xaGWVIe
         p9BvnGdOf2vyM36PHA8f2zf3whiO7Al4I8KPMBDGb4wRnFbl8U17VomdOlhPMh2UXoCL
         V9T3gpJvNfrB1Qw5ZGFgzWmGfwvX5DpgpUsEIm3uztBANhR23A1QUSZy3xjzlEgJDt1I
         9iZaAz4f4qQ/3n52IL0IiEe0RNRAx9QoNuujPqOyQW3khmKFQD94Ke+pUjaX/ERw1HyU
         WDng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ZODDmGEIbURIHmwYjhtrrv6GoCaRm1+OLLd+fZrSteY=;
        fh=yLKqIoP6L/BqnFugsGhprX3CS3ChUzjC0v9jhrTTpsY=;
        b=lSoQN0QUxqDzGKD+GMBUadX+SddEPi9h5g51Qk24ZXPmQKTHbS2XC2I5AwMZdipM3z
         px6awDlk/b8GXc7OjftcGFANYqyNKt8dyAQj2tHS/FRgIOqhhCidfsx4NRmzHJQC768o
         RWO8edWn01OrZxhG7N156hWdUM/QSoqEMq6Yw/btHRmSeBIRlpMEogKAmKLEX21+Hr5W
         rECGHCjlMbZy/ROt/IDocIsqv3TS/XoomZjq121qqJJv8kYFXqCYQtx2uzFJLP61AkCc
         wiNZSk06A8L67xE8XEWxqnG+218fDK60DsfdCvRhJqHTe/HyizIirD/pFF1LxQsqCFKX
         0YHg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ziepe.ca header.s=google header.b=dND7DPWq;
       spf=pass (google.com: domain of jgg@ziepe.ca designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=jgg@ziepe.ca;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759413557; x=1760018357; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ZODDmGEIbURIHmwYjhtrrv6GoCaRm1+OLLd+fZrSteY=;
        b=SmtYD+FlOeBT9JSlKaSiRhQsjmRSKXaBh8fVCnBXAg4EeJAMCcydF8D+qJezjoWKTL
         V8tZqIwy8j+eZkDOYifznW9Jp7kIJhqlJiW8IHCYIx30TjjtUNkKcSVnP2MgVn+AHnkO
         WsX6pJrXpxJZ1JBO3MYrRNN+uFy63B3YYaS7hhlYbtpPqkfHMcMLzBBS/iA5mw055XSs
         lPVCGV2cEOPnkV1IfEV3p5I8EEfwlfeeE2y+jY8EBnPUvYfS1gm4yhoSOU6kKh39P2pK
         okxgV0fafau71EdwgFnoWBw6f1nPb5itsy+/Mq0ejvaIiSyGuCLCBCM3CtRr8eTC+wJu
         90ug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759413557; x=1760018357;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ZODDmGEIbURIHmwYjhtrrv6GoCaRm1+OLLd+fZrSteY=;
        b=P0ebnhvqXNv8SWVcP/h8rBhyUInK8+COqVeJLeEAHlWzdUdO+d3z7EaS0L2W8qYhsz
         kqkcswUWKy5OZghYGYCCc7MSiFicPPSrREMU1K3XjDykPtntxA2etKskI5KUPWLzESSK
         PAToO9mJUcGTDW6yBdepiYqbl6WCBCECRZd/p7fYclgQkRFz6Qu9PHuN8+YTE4PV4Twr
         dysvAYeSqF6iGc3RhuReCfeYOAIMkJ/EaeWWWoUtByFNGfRQHqQnFSRQeLGpWzDFM6O0
         la7v1uUML97WvbjKbFHg92amWPagvByshLc29oev9xnncTs9w3RTwG11fnjJOFyV7YDi
         zxBA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWzs1K51MnGhd5A0pM56qIBaHSMAlL+uUGUJ4FW4LWRl9nGY7lCtWk/OZ4/PZC0b2f8AMz+fw==@lfdr.de
X-Gm-Message-State: AOJu0YzNn68xfgeEOYtG59URsVZ9rnIpG3VIcNzdd/cuaJWouBk0JONg
	Q5LViekJ1LrtR3hvSE6qZmHUqnCt+TEjMGrrzkaeFvJN1OvNQXPUlMAv
X-Google-Smtp-Source: AGHT+IEiWZqlgZ8p420c4UWIbFdgPABIxWS3BOCw3Oqu7SnwcSFxgALhH/LGajPWNFGWrDEYyQwFgQ==
X-Received: by 2002:a05:6214:ccb:b0:796:dc45:8034 with SMTP id 6a1803df08f44-873a78f22efmr107603756d6.45.1759413557261;
        Thu, 02 Oct 2025 06:59:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd5jyzIhmOxieWiTONODzS9KBvOg1h8l/QuI8zKyXBCsRw=="
Received: by 2002:a0c:ec4e:0:b0:777:667d:d0a with SMTP id 6a1803df08f44-878a050b365ls24407406d6.0.-pod-prod-07-us;
 Thu, 02 Oct 2025 06:59:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWjiPwjTEKoMUS8m++ZD4PO4sBbvE4ZcSoyjsZJgRmjnk0rlbUkmZ3rGlSOc2tgEyZYbq0PLZSXDZM=@googlegroups.com
X-Received: by 2002:a05:620a:45a6:b0:826:a2b5:d531 with SMTP id af79cd13be357-8737163a130mr984528485a.32.1759413555670;
        Thu, 02 Oct 2025 06:59:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759413555; cv=none;
        d=google.com; s=arc-20240605;
        b=ZuawOznvAGy9IqpAUogsv6nBUSeJtAkkzvSXdInfkCboRMXotXB1SMbA2niuYU9XrP
         XqNno14L08sex1ibBfXpalHFx0Kug75e+TwS1fNPpwCTyycw+cYPkTjZ2QVFPHsoEnDd
         x+n99FF3wNmqgtz3jC2qgi/nQcpOJtcAuJGI54InSygVix26ad2NBvzwm/qroM30GgW8
         WFLQwKZ3tbihlurD4Vzx2EpqMFkkAv3b0ofAb+Yz9CE/KtM19COICOG8djrI5tfpMo08
         2AwSx6m60tTx4W1nsE8IQCcvgOQDWhDiLkmTJJVHPRilVG+Ig/LTgAoeTR2AZpVlq7UZ
         Eqjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=AejVj1pzVa5tMHUAvlwjfMQqAVzkVnwGk/N4H8InPvw=;
        fh=O5i6Gc+FokEtAcS/mU/InP8xTwS9yxgaJCaG9dQPUTk=;
        b=QqKFD9TXrIF+MPn/F8nkbgFWg6mKMxQ17bgqJz6tvGykJl8QmnygLz7/NudtMh9Y24
         FFwFKZdmst8rwathDys9ix+friCDSPPgTGZhNhss/+nZ6SWSNkervgxO4p5rS1shxAfY
         jmECqVHQm54n3/9OgOhENloJTqUOH5nyxrfEj20FBNfe4EziAqwlmhhLtX4B5xUgiBu+
         7n0ef0hcZh8wLUiGX41JqQ3UCjiHZi5zX73OmOagQBhIibgVqV83GtT5pE4CWly91SHj
         la2sjv4FGjL6eLuSl/rIaLKOc/QjcvZQJ0ce7ram2qjH7Zt+MI91XDHJaxPpYYc5Ww/+
         VwIQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ziepe.ca header.s=google header.b=dND7DPWq;
       spf=pass (google.com: domain of jgg@ziepe.ca designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=jgg@ziepe.ca;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x434.google.com (mail-pf1-x434.google.com. [2607:f8b0:4864:20::434])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-87775d0d61dsi12530985a.3.2025.10.02.06.59.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Oct 2025 06:59:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@ziepe.ca designates 2607:f8b0:4864:20::434 as permitted sender) client-ip=2607:f8b0:4864:20::434;
Received: by mail-pf1-x434.google.com with SMTP id d2e1a72fcca58-781db5068b8so967379b3a.0
        for <kasan-dev@googlegroups.com>; Thu, 02 Oct 2025 06:59:15 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXplvoTpCYNE1KhESsqa9TxMLLEvRbj++xC71xTPixmuqLCpod5EXfatKPmXppjyEWSjej3zD2CSL8=@googlegroups.com
X-Gm-Gg: ASbGncs0/7VbM5cxqWwoJuZNFyJi6T+gbFhqyipUao3WK+72WgSIc98iQWquwyaVjuY
	lRAvve48vNaFgZnvZqrS6rBCqbQia0aaXr+dYXL9vEoo3cGMe9aOh5QvfnGn3St2N46SxMSkzPM
	VNAtv8ZM4vQSzO4ZbBFt0A4TjDWl1hA6FcR8A/ztT2hWgPHbJ7/DgiaWiunrqm25hWcITK1YBXZ
	82tCcIfTKStEA15lpolIlJFS4hwMiQwPU7yuN3U9oGmvWTtC5jIpgryFnzwjSBXmIch9SgxrNnj
	J4JRfjhtHrEJ/W8MBUz1qVTlpfn1+jxON/7YUagcWqiB8bmc0ELDb69oBL5yENHQ7JIh0f+cnuw
	AJ3/KaLTvOJ3i9SgAqVk1
X-Received: by 2002:a05:6a00:17a6:b0:781:17ee:602 with SMTP id d2e1a72fcca58-78af422946amr8738022b3a.28.1759413554667;
        Thu, 02 Oct 2025 06:59:14 -0700 (PDT)
Received: from ziepe.ca ([130.41.10.202])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-78b0208eb5asm2300221b3a.82.2025.10.02.06.59.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 02 Oct 2025 06:59:14 -0700 (PDT)
Received: from jgg by wakko with local (Exim 4.97)
	(envelope-from <jgg@ziepe.ca>)
	id 1v4Jps-0000000DiKt-0OJJ;
	Thu, 02 Oct 2025 10:59:08 -0300
Date: Thu, 2 Oct 2025 10:59:08 -0300
From: Jason Gunthorpe <jgg@ziepe.ca>
To: Shigeru Yoshida <syoshida@redhat.com>
Cc: glider@google.com, elver@google.com, dvyukov@google.com,
	akpm@linux-foundation.org, leon@kernel.org,
	m.szyprowski@samsung.com, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH] kmsan: fix kmsan_handle_dma() to avoid false positives
Message-ID: <20251002135908.GE3195829@ziepe.ca>
References: <20251002051024.3096061-1-syoshida@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20251002051024.3096061-1-syoshida@redhat.com>
X-Original-Sender: jgg@ziepe.ca
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ziepe.ca header.s=google header.b=dND7DPWq;       spf=pass
 (google.com: domain of jgg@ziepe.ca designates 2607:f8b0:4864:20::434 as
 permitted sender) smtp.mailfrom=jgg@ziepe.ca;       dara=pass header.i=@googlegroups.com
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

On Thu, Oct 02, 2025 at 02:10:24PM +0900, Shigeru Yoshida wrote:
> KMSAN reports an uninitialized value issue in dma_map_phys()[1].  This
> is a false positive caused by the way the virtual address is handled
> in kmsan_handle_dma().  Fix it by translating the physical address to
> a virtual address using phys_to_virt().

This is the same sort of thinko as was found on the alpha patch, it is
tricky!

Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>

> @@ -339,13 +339,12 @@ static void kmsan_handle_dma_page(const void *addr, size_t size,
>  void kmsan_handle_dma(phys_addr_t phys, size_t size,
>  		      enum dma_data_direction dir)
>  {
> -	struct page *page = phys_to_page(phys);

This throws away the page_offset encoded in phys

>  	u64 page_offset, to_go;
>  	void *addr;
>  
>  	if (PhysHighMem(phys))
>  		return;
> -	addr = page_to_virt(page);

And this gives an addr that is now 0 page_offset, which is not right.

> +	addr = phys_to_virt(phys);

Make more sense anyhow when combined with PhysHighMem() and gives the
right page_offset.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251002135908.GE3195829%40ziepe.ca.

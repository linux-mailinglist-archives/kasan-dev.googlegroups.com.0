Return-Path: <kasan-dev+bncBDV37XP3XYDRBUHRXCIAMGQEIIBUL5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 34D9C4B9F79
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Feb 2022 13:00:17 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id h24-20020adfaa98000000b001e33eb81e71sf2210484wrc.9
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Feb 2022 04:00:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645099217; cv=pass;
        d=google.com; s=arc-20160816;
        b=UkOYASZvqDCOPqB3mNckX2RGrIy2UzPa/wP3MU1qtfELON0SHbMxJgnQYLiIUYSKoc
         szPQtv/PKIXNJtyQR0bhevNSxWycTmD5pAFyGEeaNDl1LsK4z/28AE5l/R1d5CZNQB9c
         z2PDAHY7BIvDBGSlUiNI8Dubek6sDzzD6g1CkTgbQM+PAAplJ2pnMtJ9OgeIuE8WTh5p
         bSQF90/3bQvZja6fgNcE1OuWs0/qjS/EAACTuqCgrtcoFOr3XXZ/+FqhPDife9FiymfM
         aKoDpUVstZTeQJUTOdWQSpYXS1QxKdpE8pl/acc4RNBURjGtdoj3kPdT/VY2x4/JB7cI
         36XA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=VpLLfkJPR5ByrLhZKfY5cv52zkeMa8df3LmvWQ7cUYg=;
        b=ayuMPe5bFZNtylUb5ZQrkNkJicSwze/m94rruv74SVORNGdhhtl2h6+bO+VjqX/deb
         rKumbRO6z4qVySEyBMRZZcagUqp9yQNmx0c+UNOV4mGlXoka7D+b+TIQvgDTnTP6oQTF
         lv/SnP4YS4OkS4eGnCefpRSiiaPejLpFYTEUVyM05Dca3Nz814af3kDnv7IprfBuFc2E
         igNt4CRCpZxAyiHNLn710v8sLw4UbFdEok56dZostVEM9568MH2hY9Ct4rxG8m9hjLq+
         gak9TN5WFXdPJM3vIOeOWvc2P59mFSW+/6NCLX5mhJHVGei93cW1YSaFpK/52pTkMeDX
         XXxw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VpLLfkJPR5ByrLhZKfY5cv52zkeMa8df3LmvWQ7cUYg=;
        b=fxdAlQw8rJVomJm1cfe9naYmKC6pWLqwNqRYtLGOWEoOwe12vJjW9hZtlbCL2tCAey
         NuS2kD0U3W5enZ7r1b/URcvlYhE+cGZtmHHdr2ZJQcx3E3qWlUE5xgjNYIfcJeXDZRyI
         5jzOrv1UY5oO38r8EKhCUXSnsJDk5s1Xi4/oSbbNT/597Wb6ukFpBk3ThkJj95bEG1uv
         Mrow915owo5XmVNf3v9HPJJLn+vA9VItgg8qAfG5QUfV1EiDa8gBnWGJjdxu1HwKXvfK
         4zSdAlO/XODA3RjuNdL078f3r0ynHlyRfK9Ba5gFTIDSFQDbcM/qEA418HUHzV21LaqF
         6AIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=VpLLfkJPR5ByrLhZKfY5cv52zkeMa8df3LmvWQ7cUYg=;
        b=mWFcJAwZShjPpcIgHbK+t03NhO+j7BThbHIaDuLQlt+8txXf8o5pS6pZ8SFG7vJrzC
         cCOhSqT7ocPhCVprEEB8l5VXTTdn+kGinJTJtNLXIE15ZYe2K+bKsYU3msAmrEBsQJvy
         W/oYU1j6gljAp/FJAENdXXsjw1zOCQNcY/E3F4nLHxIrSt0NDUt4tG/AZ4sKmkhM8muL
         kLA7DzxFTlei7WT6iKnhMGMYEEG5q2YgzXLj/jduUJtrdQNM3s55TWWUTjot/Y7JW+gU
         M21TjN0JIlygR8Ipd70LvezVdhmyTXD5UFkTjGvvDyCvYplhrpkymcsl/cUKXsoGP3ac
         yNBA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530g2cRF0bF18nTQwjXyWlFESHoQ69nOnHT+Kyyjn6/X0yYpgSE/
	4Ind5sTiXmKUzmARHjaVqJs=
X-Google-Smtp-Source: ABdhPJwKp3ck/0xOh+qcyZV0bSCRIPAlrJdcc6L7sE9WQslk+opPYyyTcPSb993kVj3tGNfkkY/3QA==
X-Received: by 2002:a5d:40cc:0:b0:1e3:f41:b308 with SMTP id b12-20020a5d40cc000000b001e30f41b308mr2134773wrq.284.1645099216839;
        Thu, 17 Feb 2022 04:00:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1e12:b0:1e4:b617:bc85 with SMTP id
 bj18-20020a0560001e1200b001e4b617bc85ls1800wrb.0.gmail; Thu, 17 Feb 2022
 04:00:15 -0800 (PST)
X-Received: by 2002:adf:912e:0:b0:1e3:d88:bb46 with SMTP id j43-20020adf912e000000b001e30d88bb46mr2035320wrj.27.1645099215580;
        Thu, 17 Feb 2022 04:00:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645099215; cv=none;
        d=google.com; s=arc-20160816;
        b=dj1BJJxatCIww7vAA1B+XyBdO+GdYWUANDO85lL7NFuNtVfXvgfUNun+A+GKlrwpwG
         eDwVJnPomxDtVZDnc3o0BH1xvqouCgftmoaEQ4v+x1VO3omhcQFWTmxE0OMyFZ+CpJ9H
         6Gr+HF6+xaUys+9urKyukyZj7fP9fTHzq/8aIC/444Jdz7Efbxih6blUV7aDIjO8O2hX
         2c2Z5zZzapmKNbajjNHbX9bac0rfq8D3ZAKQ1sij5GDUPqYOEgEZJnE4l7s8iNue5s9J
         LT8DDUQgnw65NRs0o4k20sHsC08vq7uVPdxXNvhc+vuohyqdZhBZKpGOC6KKYs09VZMX
         k63A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=wqjOKyX5mo72rmXkkW7lIDDgIvAz/bzzAnn/O4gcYFU=;
        b=UVOHOTDuKhuztPfsOerEchG/gKJte1hq//F2hJkAtUszN3/NR3alS9HnzLw4bgCrKO
         I3d+mROsNCXo/sAo8KCBiGP37EezBaeihK/rmU/zdWwzAbo1OPGrvqNESsIs03n9zXSN
         fjaprTX6PAJuV86jENd7iKrt3RX8Sy1ZlDvelOgnnjB/EZQySOUsTu1HtIT8RpLRXp2h
         RpgKPvRoVZnojjltyuADOYmJU9WcO1Czp91StK2pwpXXTsIOgs9hP12EntvdisqDukEj
         68DKIA6TJ74wash9ioEJsTno57PSXyiyP4vT8/gKzRAHlXuae/li4xHZPXwW0XaXdyiD
         vtZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id h81si77920wmh.2.2022.02.17.04.00.15
        for <kasan-dev@googlegroups.com>;
        Thu, 17 Feb 2022 04:00:15 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id CC7DD113E;
	Thu, 17 Feb 2022 04:00:14 -0800 (PST)
Received: from lakrids (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 65E833F66F;
	Thu, 17 Feb 2022 04:00:12 -0800 (PST)
Date: Thu, 17 Feb 2022 12:00:09 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH mm] kasan: print virtual mapping info in reports
Message-ID: <Yg44yQJ9tQMgmiZq@lakrids>
References: <5b120f7cadcc0e0d8d5f41fd0cff35981b3f7f3a.1645038022.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <5b120f7cadcc0e0d8d5f41fd0cff35981b3f7f3a.1645038022.git.andreyknvl@google.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Wed, Feb 16, 2022 at 08:01:37PM +0100, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Print virtual mapping range and its creator in reports affecting virtual
> mappings.
> 
> Also get physical page pointer for such mappings, so page information
> gets printed as well.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> 
> ---
> 
> Note: no need to merge this patch into any of the KASAN vmalloc patches
> that are already in mm, better to keep it separate.
> ---
>  mm/kasan/report.c | 12 +++++++++++-
>  1 file changed, 11 insertions(+), 1 deletion(-)
> 
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 137c2c0b09db..8002fb3c417d 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -260,8 +260,18 @@ static void print_address_description(void *addr, u8 tag)
>  		pr_err(" %pS\n", addr);
>  	}
>  
> +	if (is_vmalloc_addr(addr)) {
> +		struct vm_struct *va = find_vm_area(addr);
> +
> +		pr_err("The buggy address belongs to the virtual mapping at\n"
> +		       " [%px, %px) created by:\n"
> +		       " %pS\n", va->addr, va->addr + va->size, va->caller);

The return value of find_vm_area() needs a NULL check here;
is_vmalloc_addr(addr) just checks that `addr` is within the vmalloc VA
range, and doesn't guarantee that there is a vmap_area associated with
that `addr`.

Without the NULL-check, we'll blow up on the `va->addr` dereference and
will fail to make the report, which would be unfortunate.

Thanks,
Mark.

> +
> +		page = vmalloc_to_page(page);
> +	}
> +
>  	if (page) {
> -		pr_err("The buggy address belongs to the page:\n");
> +		pr_err("The buggy address belongs to the physical page:\n");
>  		dump_page(page, "kasan: bad access detected");
>  	}
>  
> -- 
> 2.25.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yg44yQJ9tQMgmiZq%40lakrids.

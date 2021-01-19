Return-Path: <kasan-dev+bncBDV37XP3XYDRBR7BTOAAMGQEP4VL5PA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id DF0BF2FB9BA
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 15:46:32 +0100 (CET)
Received: by mail-yb1-xb3a.google.com with SMTP id v187sf24660661ybv.21
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 06:46:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611067592; cv=pass;
        d=google.com; s=arc-20160816;
        b=a8ngKxBsGGtEfcARP4eMzoGZvjK5ZrT+wAl+Y96jZXos81pc9LBr5OG0Ibta9BqEg2
         UZlhozwo4IzcXaSPc83BJ6nkc1/fc5FFVQ4bSacLKlE4wkfNYwfOVXZpUz4Dk3Nuu79H
         kq4D5BnA8s+5G39hTSI/3PCpDJwTF5NEolOEUxLhsX3OLoUmDJMCanmkyO7RqFtZARfM
         Qzxo/YfN5uKOUebd7nhvEOrIePlLYi4bdCknzVNGT73v5YB+/9Ap5qqakJ/m2/+E6m81
         cK8YcTl5keCADysAopyM56da1/EiiGlT31PSAOzaUeB7opRGW1fRqRiBy5sdr1ucHuzg
         /QSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=t6srCpVRPG94EQkU6LkE0PdE3wc555t6bxjtwK1YAtM=;
        b=LbUdbLhPNzas32I/WSj0/O2Ow0vFnQNc5Ud5ZgVbouv43CC7HWW/xAj5WdWZszPzax
         a+J+mRBhT1yIbQ8Deejiln+pUTevnYaRL8WQoC3GYj9bNtuerrCKUgFkCL+2s58bREKh
         0C5tF2nDonrzXYLFZ/31wcBHldFicMOQzA/EqN5h1LmIKutKBlZyufhXwPnvBXw4q/so
         abueewnwZzGtAHnAxRsK0oDe4Dt92O/q+0gc3sMmLAsQ5dpc8DJ2g804AqeyQuyYXSZG
         y9h8Jpkx4SSfdjJH1wisvnk9qTnZg+pPOV/tPhfx/tkzL76BmYCHYNBVXcUXtiDVK+fJ
         /Fwg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=t6srCpVRPG94EQkU6LkE0PdE3wc555t6bxjtwK1YAtM=;
        b=nTewLjN4vtY1voNejcpChP1nZpGs9+vOxqmb9BoVLOV79DOMOk0piwx7KO3uRmBlov
         1vV4SrPS4RZclupeVO3DejiCYE7G8E0c3CHq7Rjk9mEcpKF6TAa7g/z8o3sSo6jXz8NN
         gHLIYgrzWx/1c9rFX1GnNAz5r2jCcmdOj8tjXbooV8EMXMu7Rt2RfAP1nFjTSvxioM7e
         cHcwvpt0bQKIE3X8S5ZqiwvcRFKDRlqYKAXPyuCMwu1YSi5PsxK6tlYUyBpdQ5vIUlUe
         WOtI3qGJQZbzZ4TkQ4xLXAsmQQmvrl4TomXtYl/dpY5QWcqk1GP2/BgP0oBVylxwaCYX
         0w0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=t6srCpVRPG94EQkU6LkE0PdE3wc555t6bxjtwK1YAtM=;
        b=TR4cxkdDkA01boRot6F9SbmfQ1RR6nOoYQngXRZMwh56PjDpOqhMoAZFn+KpqITlsL
         nlPFaewVxPXOIulZAr3c2B/qwyIsdkiL/6fyiPmB5Qk16KVQoCd/eXXkmfs6/tbKGBRg
         WdabELkUl18uYCGNcdEg5OjrYMk5lfPInBkiCC8V98TkIr2PZKW8ivStnR+PWwi2OB1f
         zWnkZRaQ5zVBURRqu49JSQjffFSdUdglL7HzDrWmV3DvF223DYlhvRIM7kcVgCV0uGpF
         gMTIw9DKnyB4nh2l/KEJPHyyRIgCgUxtgXX4NmJDSGpj/3QYJHarlrU1pYLL8tE+2Jtm
         xZ/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531BmZsGdaX68Y4veUeA/nt9ZRICAQY1B3DSt8c7om9IRw8b6840
	Z2DLlUJNrRh9++XsTL/vVA8=
X-Google-Smtp-Source: ABdhPJzrnI99a3hYKPMScdxPOI0h2oUCs6gry560w5sZpj79MCqxKYpbtIzEwD5ahD5IyD93UnFneQ==
X-Received: by 2002:a25:d98f:: with SMTP id q137mr6596001ybg.128.1611067592020;
        Tue, 19 Jan 2021 06:46:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:b5cb:: with SMTP id d11ls10510862ybg.5.gmail; Tue, 19
 Jan 2021 06:46:31 -0800 (PST)
X-Received: by 2002:a25:2041:: with SMTP id g62mr6774473ybg.152.1611067591570;
        Tue, 19 Jan 2021 06:46:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611067591; cv=none;
        d=google.com; s=arc-20160816;
        b=eB5HKOgGgE3Q9d4Y6frl9gu8/NP4DfC3+Sb8X0uD9rOAh53DoWNec71WQ0ltcml+m6
         uKLHOeWuJj9kn9HYEb2uAwYIDqVUCfGVGQVj79u2vLXbu3MB+to8+sbBrJ7CBppQyWpN
         Wd5vqigzRsrTziKTJCwrZbV3Ld1MuAZeAtZIOPrt6WJtrXAeHaGZjBU/7IipTD751xfF
         MSVEdV+c2cQan/P/0OB3pGoM0gw5Pm45YsLvvtNOJbNQJzroLnAjHg+GfOICm0DP6rkx
         hYXvib/Vw7GVxMkRcb7rn5pwLvt07/BdZfMulbj4jzW6VED1JPEi8KjrNeyln0kTeN3x
         Jjhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=FERHyQDkdqMfDpx8QfeS+G+VfMl0V4+GsXAgpqgT4MM=;
        b=bJpvN6Keam5uLbMM8QwyvDDjLD6PUSD7p6GinYAUpUsMmW4PXFcugjKg3GqgsKPW6y
         LMaS0TSTYDigykwwoCLr+i3qy04iBsOVMXNfzAYWHjdXUy8r0RjZll5Hh4/9k50oRloW
         jTYLhg2jBPEGh4EIVqkKBvACZCgA1eRZaZCSMfxVKXNbd9uKK5kQvPwQdjXjqVxQu+Hm
         1g8xhFuOLP3S4zw2s49oHSu7VNjdvvgjtbnTiwTQ0mjA59brS8Hms08zyv40pX6/fM+F
         Jcd2IwRtllKVv2SJL+KAJS6ujngtxtotE0g2jPAL+oyEx37WG7VIw6vIJ1LXxKrOgwBI
         zouA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id k19si1863560ybj.5.2021.01.19.06.46.31
        for <kasan-dev@googlegroups.com>;
        Tue, 19 Jan 2021 06:46:31 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 0A035D6E;
	Tue, 19 Jan 2021 06:46:31 -0800 (PST)
Received: from C02TD0UTHF1T.local (unknown [10.57.41.13])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 587AD3F66E;
	Tue, 19 Jan 2021 06:46:28 -0800 (PST)
Date: Tue, 19 Jan 2021 14:46:25 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Alexander Potapenko <glider@google.com>,
	linux-arm-kernel@lists.infradead.org,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH v4 3/5] kasan: Add report for async mode
Message-ID: <20210119144625.GB2338@C02TD0UTHF1T.local>
References: <20210118183033.41764-1-vincenzo.frascino@arm.com>
 <20210118183033.41764-4-vincenzo.frascino@arm.com>
 <20210119130440.GC17369@gaia>
 <813f907f-0de8-6b96-c67a-af9aecf31a70@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <813f907f-0de8-6b96-c67a-af9aecf31a70@arm.com>
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

On Tue, Jan 19, 2021 at 02:23:03PM +0000, Vincenzo Frascino wrote:
> On 1/19/21 1:04 PM, Catalin Marinas wrote:
> > On Mon, Jan 18, 2021 at 06:30:31PM +0000, Vincenzo Frascino wrote:

> >> +bool kasan_report_async(unsigned long addr, size_t size,
> >> +			bool is_write, unsigned long ip);
> > 
> > We have no address, no size and no is_write information. Do we have a
> > reason to pass all these arguments here? Not sure what SPARC ADI does
> > but they may not have all this information either. We can pass ip as the
> > point where we checked the TFSR reg but that's about it.
> 
> I kept the interface generic for future development and mainly to start a
> discussion. I do not have a strong opinion either way. If Andrey agrees as well
> I am happy to change it to what you are suggesting in v5.

For now, I think it's preferable that this only has parameters that we
can actually provide. That way it's clearer what's going on in both
callers and callees, and we can always rework the prototype later or add
separate variants of the function that can take additional parameters.

I don't think we even need to use __kasan_report() -- more on that
below.

[...]

> >> @@ -388,11 +388,11 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
> >>  	start_report(&flags);
> >>  
> >>  	print_error_description(&info);
> >> -	if (addr_has_metadata(untagged_addr))
> >> +	if (addr_has_metadata(untagged_addr) && (untagged_addr != 0))
> >>  		print_tags(get_tag(tagged_addr), info.first_bad_addr);
> >>  	pr_err("\n");
> >>  
> >> -	if (addr_has_metadata(untagged_addr)) {
> >> +	if (addr_has_metadata(untagged_addr) && (untagged_addr != 0)) {
> >>  		print_address_description(untagged_addr, get_tag(tagged_addr));
> >>  		pr_err("\n");
> >>  		print_memory_metadata(info.first_bad_addr);
> >> @@ -419,6 +419,18 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
> >>  	return ret;
> >>  }
> >>  
> >> +bool kasan_report_async(unsigned long addr, size_t size,
> >> +			bool is_write, unsigned long ip)
> >> +{
> >> +	pr_info("==================================================================\n");
> >> +	pr_info("KASAN: set in asynchronous mode\n");
> >> +	pr_info("KASAN: some information might not be accurate\n");
> >> +	pr_info("KASAN: fault address is ignored\n");
> >> +	pr_info("KASAN: write/read distinction is ignored\n");
> >> +
> >> +	return kasan_report(addr, size, is_write, ip);
> > 
> > So just call kasan_report (0, 0, 0, ip) here.

Given there's no information available, I think it's simpler and
preferable to handle the logging separately, as is done for
kasan_report_invalid_free(). For example, we could do something roughly
like:

void kasan_report_async(void)
{
	unsigned long flags;

	start_report(&flags);
	pr_err("BUG: KASAN: Tag mismatch detected asynchronously\n");
	pr_err("KASAN: no fault information available\n");
	dump_stack();
	end_report(&flags);
}

... which is easier to consume, since there's no misleading output,
avoids complicating the synchronous reporting path, and we could
consider adding information that's only of use for debugging
asynchronous faults here.

Since the callside is logged in the backtrace, we don't even need the
synthetic IP parameter.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210119144625.GB2338%40C02TD0UTHF1T.local.

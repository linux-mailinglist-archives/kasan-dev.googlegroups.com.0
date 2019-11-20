Return-Path: <kasan-dev+bncBCP4ZTXNRIFBBYGE2TXAKGQE7KPOL4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id B48BB1038A5
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 12:24:16 +0100 (CET)
Received: by mail-ed1-x53b.google.com with SMTP id c11sf16137251edv.23
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 03:24:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574249056; cv=pass;
        d=google.com; s=arc-20160816;
        b=eQhaHPx9ZRotZ06FwIOojpHcnMLSPG6I3ZajP9cScpc2j0kbXotxq1eTvrDaq/0ZYT
         0TLDC7lcRkAN4i88mLkfziQ9HLBr83aKRT2l+DA1A3IVO8qvCaY0NBWxLkA5gnzMV/D/
         Ro/5ZEt4HfrfzbpeGxBQ69eEHlOFJIheFYPros+HuJcHqnCZGjsFXRMNe3qGu8fLA7FL
         pfEjRFkXDl+j6KAlcZk8/889AJ2FysEfKlHPIcD/amHbEM1e9e3S0HI92c4xxhI+gFWT
         XuvcSJvklsQZRR5M+do/PaSTaqabSzNwPySm+5lkJJt9CVcQ/pygTe+UhUUMHiFWO6a8
         K05g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=k2KC4HwfUU4haxLVJdfpXJouP3OPITaTTldl5I5JlSo=;
        b=YWelR5yoZa4t3Rc3c8gWOGU4p3MS0zvBPVStfE++nyFqEdE9YYQKhWQmnB4fFQtMNo
         gf9wt8ZFFHr8RnipZONUwSz0EmLk6Se7rr2H3iXibfusw9wioGovNO4lbJioBicN1OGZ
         0DfVGnn5vhnaaXrjpC5CGDiV9lxa+hzBimbJc5Ls9yc5Ryeb2gYOSQWjdC04lw5k62x5
         tSjNBRn8AHMvaL9vBr1WC6gkQAaZrPBx65k9KbTTrIa4mvLF+3VaE1aLw9JV9tjA1Rcf
         VgJqEL4+jHkzDddchxXaHUSWKvv+7FUIR3TaGzglCKR1x6rnDppnOuGKR8jzLRJY/K0D
         03bg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=VHGB9cNm;
       spf=pass (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=k2KC4HwfUU4haxLVJdfpXJouP3OPITaTTldl5I5JlSo=;
        b=tNWHWC5YhtGCIKxyGKUd9HHswzzJj6n6P+hYULkVHPqrRUx1QNaXSqPBFa3iRJw5AP
         U/D+zqju2D1G1s4BApf940yZ23tRbs5WE7msuwZlPjExtpSma0+wRD9YqaEi64Kuf2GI
         j2pNvNERY3VQXKA6yOjQuGxYsE7iUVsQOQIkicDVd2pag2tTaUtKHKzINyrPtfuqlXuu
         KLTuYNgCSdwOYlD/gl2gRntD3qr2lpIEJX0a3jMltAcn26eH518SvFyS/Eq3A0IMNmBn
         QcNg0bIQ1knXtXoiogflFdB7XRbHKSJrYHBrxQkNSvASE1Kv3YgCEarHOBNqKMLlPz4j
         VqHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=k2KC4HwfUU4haxLVJdfpXJouP3OPITaTTldl5I5JlSo=;
        b=Q4qtwKVG6ZYcnX68QYt17bvrbwDiq/kQG5PQTe3HIdPRuG02EWSxMgZ8cb940U3cT0
         dToQEV4ETHui9G13ByjHgAPCdcyVITUTMAD54iZbj8FHQd9wnQKmMIKwA8TL94Tqsu0B
         9uvpvt9PkbncxbUn1el7qyRq0LCwtzhurdwCQTVQjZt1TRHiDz3B1dhO2gdXrFatIr9E
         QBYaxkNx1bYzJdtRq+HqZ2W8TsoF0x8s5eQrQuamErQulERd2ZFqr3DAePhnnrmjbhfp
         HK7VN2f4yu8a0lk6VyiRuPDvCdkhBLKRz183xXqOyme1dCUeURUtezzXRf9rC42VUStW
         xYBQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUqogA4Q7fnwfGXl2fEQgbk8uuPR3mLP6x22XSpmsdPjNUKEH4p
	25LrmsRgq44ZjHFE3B9oSww=
X-Google-Smtp-Source: APXvYqy3FKIxkDJU7s8DZ04nW8Wcq8fNlMIBkIBzazEzt7h4ldCcHd1gNPOWcQgJ73WCUSSux7eAvw==
X-Received: by 2002:a17:906:ecad:: with SMTP id qh13mr4913570ejb.25.1574249056442;
        Wed, 20 Nov 2019 03:24:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:b245:: with SMTP id ce5ls946301ejb.13.gmail; Wed, 20
 Nov 2019 03:24:15 -0800 (PST)
X-Received: by 2002:a17:906:3919:: with SMTP id f25mr4864598eje.210.1574249055980;
        Wed, 20 Nov 2019 03:24:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574249055; cv=none;
        d=google.com; s=arc-20160816;
        b=ckyQGdL+obP2DIXDPHRFbpwSjkFY6khr6blXkdWhgX3oltWzLqrgFgJudndHikPjK9
         OVp88UO5z+O9u00u6i8xkz63dpVvZps4YyWbtSHp1amqgCGj0MlUrvKOV9aVVWuWt55T
         bjp8Y3Hu+jLOsx+TRms/NBOk2ORzo5k+pByuWWf2t6qwSOVC3Xv0tJmGpnvHTx+h0lZ+
         PUGNdIQDtLqIB7zGF6xjaWpTJ3Ap1yDDWw+C7pygikRayITKcdmmL38tgohC7dvpr+ws
         jUWgdXqlrn9lcIIaSo/mqa+oVREECNXvNNNkQUikmSjc7L/vwnqr3BczYp94sI0Y0Ezn
         ExHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=XrrdFhCCBXRxT3LV1xr012UV8zCjBvEuijRbqOYas5I=;
        b=To4JsaKo45XvtNp+JftcP6LZOrUSLFhHfR+16bLS6adfhRskLC6ejcm3HAR/mdbDuz
         Dq4mKdzuTnbblmyhe39pqYIDx2+1psutsGtjCA+jC9xzLm68FZi94CZhCIxkZPwmlZUh
         /jDlnKmR1QHzsnGdGuhURSydxxqgmDCsCDRLwDcDf6P+gM2Jz5JIvY8YZl4OSmR5HM2P
         XLLu7jL+Mc0/RQPOEVoiLvgTiw/02PCZ1vGpcF+t1yTWRo7wv6JvW+52jHwpVFLW3QVk
         U/EH6rp+KL1K7Bnw0/VK/tm64K3umvdl/9hjHpF0qUuHPjXENJZy5mCsojw4tOdrP6pG
         ebKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=VHGB9cNm;
       spf=pass (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.skyhub.de (mail.skyhub.de. [5.9.137.197])
        by gmr-mx.google.com with ESMTPS id w4si291319eja.1.2019.11.20.03.24.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 20 Nov 2019 03:24:15 -0800 (PST)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted sender) client-ip=5.9.137.197;
Received: from zn.tnic (p200300EC2F0D8C008093FCEEEFCF892F.dip0.t-ipconnect.de [IPv6:2003:ec:2f0d:8c00:8093:fcee:efcf:892f])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.skyhub.de (SuperMail on ZX Spectrum 128k) with ESMTPSA id 4066A1EC0CDD;
	Wed, 20 Nov 2019 12:24:15 +0100 (CET)
Date: Wed, 20 Nov 2019 12:24:08 +0100
From: Borislav Petkov <bp@alien8.de>
To: Ingo Molnar <mingo@kernel.org>
Cc: Jann Horn <jannh@google.com>, Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, "H. Peter Anvin" <hpa@zytor.com>,
	x86@kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>,
	Sean Christopherson <sean.j.christopherson@intel.com>,
	Andi Kleen <ak@linux.intel.com>
Subject: Re: [PATCH v3 2/4] x86/traps: Print non-canonical address on #GP
Message-ID: <20191120112408.GC2634@zn.tnic>
References: <20191120103613.63563-1-jannh@google.com>
 <20191120103613.63563-2-jannh@google.com>
 <20191120111859.GA115930@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191120111859.GA115930@gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=dkim header.b=VHGB9cNm;       spf=pass
 (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted
 sender) smtp.mailfrom=bp@alien8.de;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=alien8.de
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

On Wed, Nov 20, 2019 at 12:18:59PM +0100, Ingo Molnar wrote:
> How was this maximum string length of '90' derived? In what way will
> that have to change if someone changes the message?

That was me counting the string length in a dirty patch in a previous
thread. We probably should say why we decided for a certain length and
maybe have a define for it.

Also, I could use your opinion on this here:

https://lkml.kernel.org/r/20191118164407.GH6363@zn.tnic

and the following mail.

I think that marking the splat with its number would *immensely* help us
with the question: was this the first splat or wasn't? A question we've
been asking since I got involved in kernel development. :)

-- 
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191120112408.GC2634%40zn.tnic.

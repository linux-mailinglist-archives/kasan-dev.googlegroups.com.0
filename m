Return-Path: <kasan-dev+bncBAABBX5VX3EQMGQEMI7JSWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C1D2C9D8CD
	for <lists+kasan-dev@lfdr.de>; Wed, 03 Dec 2025 03:05:21 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-477964c22e0sf2989165e9.0
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Dec 2025 18:05:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764727520; cv=pass;
        d=google.com; s=arc-20240605;
        b=W14JTFvZjW8lcPkueU8p/5DQH8z9WdqRWVDUL4gIlI33+1r2mXFtAUsb3AYIxf086V
         zl51Mv9RZIQx/K0gY+L5bv8dRdVn2O3cg0SXVclX553AWGrurUutM7VaBd72cqC9qfJ/
         ixLBe/YDAUPUYbW7I249MvIfIKVEUCq4e3ubWBsb+kd5w4QHcHrzdPLAQl+w274cO20f
         bjXMQRlQ+mBXO43Klk2uG9FGG0EyKXxTPuwwS3H4XGGTZrlT0uIhX+mRThbX4jcxnqCW
         6XrspWjFI8tyWRxkYKJG7UWnhsUdfIE5O1NgTGeJh+vkCF5pWA1lRehi2NNR0En4KlDT
         VeNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:cc:to
         :subject:tls-required:message-id:from:date:mime-version:sender
         :dkim-signature;
        bh=QAw47C483nS03yLwRgjhic6nvC9gCHoFsNcVtcJQcVE=;
        fh=mdcU+niYY6YePYbwnooEh9ZiNa5PfKPvChuwpn4OF7A=;
        b=dgsO/TQr6pIiT8AsxH+IND1iC/gjR8DpB/YoJUR8jyoV6SA+LYQjT2Sgvx45w6MOuN
         EivT+7r7YRTx0afZS/ecHEiWlf0Z5HH5e5LeqAr4zOz2gECBQwozx7DxjBuequOJ+irw
         pzYuX7bepqI7MFV06EdhNHZkJzPxvEGNagq9DQZe4Yecoew6/N1Ul0dyg+o1LUXIAbU+
         CbjdbaSZKx3IB+8RdlCeCTDJ65mz58xjZ4FhCmvJDefEIC9LhwDXbd+mSmQ4Tnig+NPp
         AF79WhTNTRuj4NJ7u1S+qC8UpdfefMaA3JsiaVi5CedRCkxU7V1VguMPaakT+fEa2fxU
         mXrg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=U7HNZreu;
       spf=pass (google.com: domain of jiayuan.chen@linux.dev designates 95.215.58.171 as permitted sender) smtp.mailfrom=jiayuan.chen@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764727520; x=1765332320; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:references:in-reply-to:cc:to:subject:tls-required
         :message-id:from:date:mime-version:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=QAw47C483nS03yLwRgjhic6nvC9gCHoFsNcVtcJQcVE=;
        b=elkRiUgvFf9d4Q1mzHYpO/lT/LP3cplcjTyQN3OEoIGbPv+KzQz4+baiLMgOIRDwAb
         Uv/DgQIlXNotLHQEZCe6QAw1PQbbu5Jqg9LeSfUmv9ntBfpg9zbvBqsUYfagMMdH/lIh
         RsCaeIlwGMxRh/nlaRQcLFd/0kcgPxg4To0MJ6LVSWwd+58xW0RtFv6ynK59SOOqQBvH
         f28uow0p21O0/ff6haNfKgtt03waX+VmuCAAAcYm5pMI7WgIlOCqP/Tf5prVmE9C75WA
         oc3UmCVS0vLsEs5DHdvLBag/rRsSKjednhICkjbG03LXfymLXyCTUq4eh32nI8hCjz7T
         KXgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764727520; x=1765332320;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:references
         :in-reply-to:cc:to:subject:tls-required:message-id:from:date
         :mime-version:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=QAw47C483nS03yLwRgjhic6nvC9gCHoFsNcVtcJQcVE=;
        b=hJyzVMrRrUOaOtiNByM9++YfqeNBPOxphS6uWsm2SldeAfI1TSP08bcsePbtYOnT5y
         9uinahYzhDsNMGguQsd+sloBNs92c7STFdDbiOVaVZDt3lxCKMH/hcbp0zq0KHe9vo2g
         u09lZT6Vw7oj5cy6sGI9dyRM3YgIROsrjszhmNlxtS6zL950J9gqmR8twSDUQ+i9IF+e
         W/C1HmPs7B+5+BTTBAx8Fc4tqJNmEg40klSP+RAaME3rT+idIS1RpjQm9lpujcj+Cs5V
         A971jjxEgpnWWMve0vovPf5jW8BOlxHMzWG9h+cCbvvllz/OS44rHFNfQcEQ58/pUiaN
         Qn/Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXCQMMTkWjG4HW1kBc4UlNTBNVVfdBDTynBQqts9JDZB079Q8Gt90IoRadJjgW95BUxlvAQ4A==@lfdr.de
X-Gm-Message-State: AOJu0Yz/khV1pb2IQtz4iHBz3MT+EBKHFf76XbVf/3zS7+9sGdwCjOS5
	S4WEswV0XkCA6aReCFDESI2t6x7enANjkmDzsg5XclLqou7HzEutUPjB
X-Google-Smtp-Source: AGHT+IF78fdD0lD6KCJxT9JEgYpuhn1qrj3ymmFcj5Cak/qH92lXJukh7cl/LDxw1JCuyXDCXWL58A==
X-Received: by 2002:a05:600c:6c10:b0:477:a71c:d200 with SMTP id 5b1f17b1804b1-47926fc3d63mr34018705e9.11.1764727520427;
        Tue, 02 Dec 2025 18:05:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aslJi7oaLydkVk0fZkl69AKUpJP5VyY+jeys4/ot7cTA=="
Received: by 2002:a05:600c:a49:b0:477:a036:8e6d with SMTP id
 5b1f17b1804b1-4792a7800f8ls1354855e9.1.-pod-prod-00-eu; Tue, 02 Dec 2025
 18:05:18 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXDfIe6VyCvBlnoGPxlbb+nihjfylP3GvbCykp9kypBsTXekBppjvmrAC8ffIkn44sdWGbUYwSVIM8=@googlegroups.com
X-Received: by 2002:a7b:cc0b:0:b0:477:3fcf:368c with SMTP id 5b1f17b1804b1-47926fc40ddmr33986825e9.9.1764727518015;
        Tue, 02 Dec 2025 18:05:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764727518; cv=none;
        d=google.com; s=arc-20240605;
        b=c40RMYQOwZkp3Qqj6MfNz+18Vx3iOKlob1LQMxLiFen6zm7i4Ls8m16wAzmezbmsyp
         FVqap5DQnjbaB6xk/fMqsufDiUCxWtca3rETytt591pa1ysarD/oEQyykHpgdMH9JGM0
         m97UvqpWswtqYeL2iRcq4IjQnhtE4+QYwTyDjZ6rZnfjZgvoFTQGA/O0rOSeFGY6E2vH
         enU53VJizhEQ1JVl89GOmfGPAHn4G7B8SfpJDD8Mr2Xs5SYrkJIwY+STgPw+iGutYCT6
         YfcHHFdKsS7xpCNQs3OVsE2R6TNmwCxeaxx8NWGoIIyTLN4NcU1hbpRy+IBTnqYPVW0R
         Bdjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=references:in-reply-to:cc:to:subject:tls-required:message-id:from
         :content-transfer-encoding:date:dkim-signature:mime-version;
        bh=FPy21LS9S9ludFgcJ2xXTrctbrNoQvJ7KLCEgrlMWY4=;
        fh=wFRjpG76xvr8+VtaaR8Ex3MnOjl//qUWaKUInCQe1x4=;
        b=Q48CB+dJMRG3tYA+a9ZKvZ2wurCUbLRuVtu2qTrIuFy3AP1TMovAIMAOUD8kLGA+hA
         2oHD7ya+LrxjbD2mR8ccae7rcnexnMwVxtiJGf0pbWu3WOVlr084x5BqjsiafvQLrKgw
         dKqp3B7rGLynjcXk/lbd/7LwC2iAwcLvJu+fwuDOxU5KE8Z4hRhL+Ro8PSKG36yl0QWm
         F3Rk4N5abunaYrvqVnlm09FwQB5fNB26aV039tyTSW2pPQ1lI2r3DOUmkXCbbhCpNlzU
         CmvOP/U/5FmkuxJwm7krZ+Labfd0WESSROhVZEWMw+vjNZYP1Pj39ShY8xI3ZGwSptW9
         9NAA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=U7HNZreu;
       spf=pass (google.com: domain of jiayuan.chen@linux.dev designates 95.215.58.171 as permitted sender) smtp.mailfrom=jiayuan.chen@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-171.mta1.migadu.com (out-171.mta1.migadu.com. [95.215.58.171])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4792b029202si63055e9.1.2025.12.02.18.05.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Dec 2025 18:05:17 -0800 (PST)
Received-SPF: pass (google.com: domain of jiayuan.chen@linux.dev designates 95.215.58.171 as permitted sender) client-ip=95.215.58.171;
MIME-Version: 1.0
Date: Wed, 03 Dec 2025 02:05:11 +0000
Content-Type: text/plain; charset="UTF-8"
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: "Jiayuan Chen" <jiayuan.chen@linux.dev>
Message-ID: <fe3436bcc785ae432edb9a24aa8993e8d25dad9f@linux.dev>
TLS-Required: No
Subject: Re: [PATCH v1] mm/kasan: Fix incorrect unpoisoning in vrealloc for
 KASAN
To: "Maciej Wieczor-Retman" <maciej.wieczor-retman@intel.com>
Cc: linux-mm@kvack.org,
 syzbot+997752115a851cb0cf36@syzkaller.appspotmail.com, "Andrey Ryabinin"
 <ryabinin.a.a@gmail.com>, "Alexander Potapenko" <glider@google.com>,
 "Andrey  Konovalov" <andreyknvl@gmail.com>, "Dmitry Vyukov"
 <dvyukov@google.com>, "Vincenzo Frascino" <vincenzo.frascino@arm.com>,
 "Andrew Morton" <akpm@linux-foundation.org>, "Uladzislau Rezki"
 <urezki@gmail.com>, "Danilo  Krummrich" <dakr@kernel.org>, "Kees Cook"
 <kees@kernel.org>, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org
In-Reply-To: <xfqnzil2oiidogd2drvjrzg4dymydywkge4zws2dildgqvcr2v@ns45a6frntpf>
References: <20251128111516.244497-1-jiayuan.chen@linux.dev>
 <xfqnzil2oiidogd2drvjrzg4dymydywkge4zws2dildgqvcr2v@ns45a6frntpf>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: jiayuan.chen@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=U7HNZreu;       spf=pass
 (google.com: domain of jiayuan.chen@linux.dev designates 95.215.58.171 as
 permitted sender) smtp.mailfrom=jiayuan.chen@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

December 3, 2025 at 04:48, "Maciej Wieczor-Retman" <maciej.wieczor-retman@intel.com mailto:maciej.wieczor-retman@intel.com?to=%22Maciej%20Wieczor-Retman%22%20%3Cmaciej.wieczor-retman%40intel.com%3E > wrote:


> 
> Hi, I'm working on [1]. As Andrew pointed out to me the patches are quite
> similar. I was wondering if you mind if the reuse_tag was an actual tag value?
> Instead of just bool toggling the usage of kasan_random_tag()?
> 
> I tested the problem I'm seeing, with your patch and the tags end up being reset.
> That's because the vms[area] pointers that I want to unpoison don't have a tag
> set, but generating a different random tag for each vms[] pointer crashes the
> kernel down the line. So __kasan_unpoison_vmalloc() needs to be called on each
> one but with the same tag.
> 
> Arguably I noticed my series also just resets the tags right now, but I'm
> working to correct it at the moment. I can send a fixed version tomorrow. Just
> wanted to ask if having __kasan_unpoison_vmalloc() set an actual predefined tag
> is a problem from your point of view?
> 
> [1] https://lore.kernel.org/all/cover.1764685296.git.m.wieczorretman@pm.me/
> 


Hi Maciej,

It seems we're focusing on different issues, but feel free to reuse or modify the 'reuse_tag'.
It's intended to preserve the tag in one 'vma'.

I'd also be happy to help reproduce and test your changes to ensure the issue I encountered
isn't regressed once you send a patch based on mine. 

Thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/fe3436bcc785ae432edb9a24aa8993e8d25dad9f%40linux.dev.

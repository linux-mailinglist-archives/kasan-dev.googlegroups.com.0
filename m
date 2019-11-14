Return-Path: <kasan-dev+bncBCP4ZTXNRIFBBQFQW3XAKGQEXBRH5EY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 969CDFCCD1
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 19:09:04 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id w4sf4906884wro.10
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 10:09:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573754944; cv=pass;
        d=google.com; s=arc-20160816;
        b=qVWJe7w5rgvM/8Hvd/692xw0a8rRfhd+yl5ki4ld1fjjpuFy7asAFP6+MKRdHbIsnQ
         a7fJss6KA3bHplqfAGEz2kdyqVteDN31S+/+Hcn0pqClmOTsvFu2lhpgdnS6dCee+fLk
         z4wZyIfukqHU29PJpFQsXGUgvKxPjW2ljlxRXApR5wkOwg3NLAMhH8E4WS7VRrwPS+op
         joPHTYitGjcuqDy9VEpmxrYmSsyTLPYtTx78D+zWqHLlveEcnI2bOAWJmf9NI3OCNizH
         AJhfmmEcwnxxMGopnxpMp90tca8nWRDbBhJYAFifs7+hvpogybk6ZEcSOvwkNGgOmiZa
         fBTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=VVn1FaKoz/zqJTH86TSQ2WETbHsR926NiNVPX1qgnJI=;
        b=PjtjvA7bM+XRq3CRJIr1QM3dFCDP/nP6sEUpZktH22RJAvz6RX53cYEf78k8TfLlZ8
         6dmzPUHaVmNt0qdyfDYAg/s4EjBjpoTbW3b9ogBQS20b5zwsN3RabazG5M5s9AUKiUjG
         thoAkYgFsqg/fTW3q7Anz3ExdaBYSP1AOWEm2DJ4aHWa7Xec7C+unrvCScYcHaldJ/dA
         PpMs/1J7hQI62pzd+Sx6CavtKbXZ6C4PbCAyrOWeY9AAoSk9WSJDaOcOElrKiD5RsgB4
         LXQYyahPD+2QJEQBheAf+mQLcfG3sSzbaCvKn7yW9I1URRW18/HniPzrgwHFF/4+7N1T
         I2Tg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=QU2oLMr8;
       spf=pass (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VVn1FaKoz/zqJTH86TSQ2WETbHsR926NiNVPX1qgnJI=;
        b=n5kP9EZ9sta+jI3R+GNtzueR9j8D9NlwTu2PoJkoCGDwbNnb41usb5L5cAytEYqt28
         9RhBJLxg+0iBsThwGf7ls0gL9fRdYAg4/zalTtz4ymNvBSmFNWq6xnYM/VI+4aOFd6rx
         ImUz6lJdmP2r95G+mlPL2XQAvv5dd35MZ4o/RJ+4PPLarM4pwC3tpKm/hjRWPWWzwfLP
         JmSoAHKsTzRPLItvBnwR5xPPFG5R1/yHwu09li0yx9N+kMi1MKzP6Y3vplHYsVHhotzc
         F37QEE1ixBy/fumPXTNNKicS1k8StoXOVo3AMdmPFMKg2uSd5fZLK7Y4ollWMy4R8Fpm
         EMsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=VVn1FaKoz/zqJTH86TSQ2WETbHsR926NiNVPX1qgnJI=;
        b=tNoNt5Q/iFfobGye9BZNneMuAD+z6ziiyce4lMLYRefDCapMXOsFd8XLtK8STR42CI
         GqjZX1eZgU9Jjkc0evHx7IkiovldFcxG22/gdwKmffpR4wFlk6tu5az3TA2YlWvS96Nf
         268WOMP5vT20XraXw9qbjjoyxZvegB4oXJgpwcWEkHpS0uaLCDzbidnsxvoBE8zhww7B
         pwfQo2d11BKwcadOdHAyoeebbxPOhXu9q3mXaZGawdYsqbSkZg8gZvQ+xkOncVO8vszM
         /ViETNlXMuuA8dTHcTyCqu+dopP64hWiaN2uo4aYTX6JQRM4kC2Q8WMrVaJaggQH0VJ2
         lA4A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX1Qal6yWNFbf9AV1/tgI0MoMc1cr4nZHtqxTQ7pAkkPDGsPaJ9
	V9eGzhUe0BdEx4Afmq6qBhk=
X-Google-Smtp-Source: APXvYqyfni6///iN9YvTldWcGTcfzXAKV9peKyEwIGxK05Bc+hP6BcR4IZK4Hr+/7E0++vcZ3ie3UA==
X-Received: by 2002:a1c:e154:: with SMTP id y81mr9284985wmg.126.1573754944296;
        Thu, 14 Nov 2019 10:09:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:44d0:: with SMTP id z16ls8802881wrr.14.gmail; Thu, 14
 Nov 2019 10:09:03 -0800 (PST)
X-Received: by 2002:a5d:6548:: with SMTP id z8mr10407021wrv.273.1573754943722;
        Thu, 14 Nov 2019 10:09:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573754943; cv=none;
        d=google.com; s=arc-20160816;
        b=QCL/SCnpfO4DFBo8v+XM/NhAYhhqVZgjP99dsCtRF3OqHx/wizDn9W+FwsMnc3xZnk
         fhH8TnoXTV9U4KxhH5JpJ+3Cvg23jZnzeNKMFO5Uo2f9NcTtsC4ldryMpRYxD4Tz9Vo1
         QErxb7aKJsMwbIFy/bReg3F1QZYoJorXcuc2cwaLlX+GYGc6o48yFbHdiQ07yAtQfnfQ
         FkpxFVEZ9WBV98fOQRGQ3RpqZDRAZBasKFcsMCDrbXeNbJqMvAc8tv5boqXq4do31x3W
         FrR90Q/zqovdfJDaDdOij8K519x7yUtnVI7EcR9kglLLrsJxiuWNGqD7pa6oKfj0mFqB
         Cv4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=8zyhxwqKTlBkuN/gtzYWICTpVbITCgZCs6VEKV/QQFE=;
        b=0XnzH/eOyllPM6SojX4vgnwvQ1dABBtuCmeKa3tN9ezEKfFIolrqwxgkjOG0Q9Er27
         KGoJrzCRy0A1k4uUiWV8BPxeFxcFpUgqy/StyJSDQfIE9T8h3ZrhWurtiTovW3b7pLdJ
         Zs7c735ePQ73atg6Q2hLWTmvLngN9aqW3PX3Yn3Meom4VpO/7GNoJp7l99EFyWcqXnxL
         k5LSVNML887yDxmtnZkgxdHJNoDCvHKltWrbNIWvVy3BZBvxE60Sq0W6ud1O4NeQY2Rl
         gc4t0fELjtm4BuwuTCco3uoycPCEbDwzojPUN7y/VPobcFk3kmxfjg2IWuhge/aM034t
         97zA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=QU2oLMr8;
       spf=pass (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.skyhub.de (mail.skyhub.de. [5.9.137.197])
        by gmr-mx.google.com with ESMTPS id y188si474939wmc.0.2019.11.14.10.09.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 14 Nov 2019 10:09:03 -0800 (PST)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted sender) client-ip=5.9.137.197;
Received: from zn.tnic (p200300EC2F15E200329C23FFFEA6A903.dip0.t-ipconnect.de [IPv6:2003:ec:2f15:e200:329c:23ff:fea6:a903])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.skyhub.de (SuperMail on ZX Spectrum 128k) with ESMTPSA id EDBE21EC0C7B;
	Thu, 14 Nov 2019 19:09:02 +0100 (CET)
Date: Thu, 14 Nov 2019 19:08:58 +0100
From: Borislav Petkov <bp@alien8.de>
To: Andy Lutomirski <luto@kernel.org>
Cc: Sean Christopherson <sean.j.christopherson@intel.com>,
	Jann Horn <jannh@google.com>, Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, "H. Peter Anvin" <hpa@zytor.com>,
	X86 ML <x86@kernel.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH 2/3] x86/traps: Print non-canonical address on #GP
Message-ID: <20191114180858.GA8520@zn.tnic>
References: <20191112211002.128278-1-jannh@google.com>
 <20191112211002.128278-2-jannh@google.com>
 <20191114174630.GF24045@linux.intel.com>
 <CALCETrVmaN4BgvUdsuTJ8vdkaN1JrAfBzs+W7aS2cxxDYkqn_Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CALCETrVmaN4BgvUdsuTJ8vdkaN1JrAfBzs+W7aS2cxxDYkqn_Q@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=dkim header.b=QU2oLMr8;       spf=pass
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

On Thu, Nov 14, 2019 at 10:00:35AM -0800, Andy Lutomirski wrote:
> And I think this code should be skipped entirely if error_code != 0.

... or say that the #GP is happening due to a segment descriptor access.
Would make the figuring out why it happens a bit simpler as to where to
look.

-- 
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191114180858.GA8520%40zn.tnic.

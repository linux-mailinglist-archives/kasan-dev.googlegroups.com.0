Return-Path: <kasan-dev+bncBCTPB5GO2YNBBXN5UPXQKGQED42RQUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3b.google.com (mail-yw1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 91FA2113F90
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Dec 2019 11:41:34 +0100 (CET)
Received: by mail-yw1-xc3b.google.com with SMTP id e124sf2039945ywc.10
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Dec 2019 02:41:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575542493; cv=pass;
        d=google.com; s=arc-20160816;
        b=SYx9ebIG7KEHbxCmOW0e9FnqqHzWi3haRkrZCe/XG7u9QcqAAS2yG63AlrIvq6whBy
         wM16duutcMFW6OddU04yYN93PchujyuLEv2TWL1FjlzWQ/WJMd1hLByk38OjJ0FpK0R+
         VCXCGmY6WM34pGAwf3kK9GOq5B5hd28VDfdYS78oI/cSytUJ4aecKK72Tq3bY0vCDCnV
         U3mMH140hHtkfTDDFehuliqrzsoOe9L56fcWcsJO+1baE8joVqdMep/klo0FDaWfkZv4
         P2c1ErnqE0hKY8P9F5Yr+K/Ge6L1NbejrGCobhARv9vMPWM7zg3vVzEAxggLHnzr+wgE
         ANmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=IZ/BfqeO9uzs3LV4wm3iGwWo13llmendZiM+zxoVYgg=;
        b=codybaiQSfeWt5NRLxMnQvjCZP930+bV/E7tYTBnt2IUGPKNR0LTJn9GhEeDLCu8Jt
         3wKJUY+ANuLuOyqFySKDbsS/ksjUs6iTjWs52gPJqkREKKf/VceLUTC7ZPiRKbd95eKb
         khGY785sDpkW5Qw7Hknbeo9lju9jKSjW4Vz1++ilCa4cZfM8hszw+fks1a+1X/Xf1yHw
         mIrC4zlUx8v/GXMkuAEyVaRC43BmvUjWGsux+wkmh9fUmfXfibCqzV6VtfuDCsZcQI7T
         F7GDszwFi/CbsxQRYnbKnpZOR708NJ5HS/xrQ4Egv8yJQYKOQ1fzZFoY/sWtBDEh3oNd
         KxBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=IZ/BfqeO9uzs3LV4wm3iGwWo13llmendZiM+zxoVYgg=;
        b=ZWI83EWXxK7XPY30XFMSj3s/TfsYc3sTYJ2Pc7IAjtRK75wIP4TqZhy+jQVisAf5U7
         NOIAgSJbcwFNYxFK2nI9RCednenEEr8c3S1XgfJQg5GiQzJR7kh4aF4XdNAOC9xB7fah
         DH39Ve/fJ6UvCYnZIB+epPxP5hVcNuWS1vBG8GBJgWJKugsB61RbF+bFpxpWaL1fwcb8
         fzvlcqywHQZy5clo7J+DE7djhgvydOQkV8Z3d5LSCI48qfzRovmdtWNQy+4Vl3qpm5m9
         gMy0q01opd7kodayK5T2lYZP+1Y5SOj3UbhUEF3PUFIBZTIVV2bh7RO/GfClqXv6/li5
         Wh/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=IZ/BfqeO9uzs3LV4wm3iGwWo13llmendZiM+zxoVYgg=;
        b=W4tt6xAy+oG7cjHUQX7myXM2V4+UZre6IyFW2zgkxbVhdhjkPidYI+d5DWCK3gIqsA
         G3HUdBCMbJmFqXtwDo61wYy5V2cU59POXfvi91GacpRnPR2Fqtbyi58wTsBNX0bz/ij+
         cvLoidspdW6rXuZiPGz1HuU4gVFL0qBYruCvHsZ1nl7zH8jYnpgpODeG3QF6S0NShxlI
         WB6AHvbtGi4bQ17w0m9SaRtMCseqzZMwlcU4gtGapMCF+kQY32bw3OjfwIOC+UGwxVax
         amiGjypAo1ZURGs+ly7+z5NxvaBa8d963deBS2DSz9FZqAvOd4DdY8Ua4PMnEcdZh/Z6
         aeRQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVzn+Xd1q3hWr+cPmhWFPSu8TpqNpz40RK+Yj6EVvESzsXBYN+G
	s+1IfVQt0Jexc0PDi2YcD6A=
X-Google-Smtp-Source: APXvYqytzDcHSpUY1Jthhuf+46U0VFKPBf8Lm8ZlEFe3R82LF+iLe4e8wiq28PxqRg7BVBSd45eaGQ==
X-Received: by 2002:a25:b219:: with SMTP id i25mr5611774ybj.195.1575542493549;
        Thu, 05 Dec 2019 02:41:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:481:: with SMTP id 123ls388334ybe.1.gmail; Thu, 05 Dec
 2019 02:41:33 -0800 (PST)
X-Received: by 2002:a25:d601:: with SMTP id n1mr5748622ybg.497.1575542493157;
        Thu, 05 Dec 2019 02:41:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575542493; cv=none;
        d=google.com; s=arc-20160816;
        b=cOUsxGd1i6mryoDaCQyFDiKCWxrcJoKG/iBwpYIO0uN+wy2uAWQhQ4SCr8FXbcBb7e
         VZsuQhBcZUZjrc2k2GnWmW7neWUZ6t6urSq7R5ERKDWEubYFTwmJM1LrHkToEgdsswOz
         wvEntVpFrrc4SxNcCetN059woHZKEvnM0Xihv/diYZKqLbXHKhc1lQhhXLMK1h5R8FJJ
         oht25uS+3FXiCb79bjZCjZTRayd9OR+a8w4RQcBJWCKefEoYm1TQjZRtQoQFqCbBP7ul
         dhCH9+koYEApZZt4OAC2vO7zE1pAGtCmm6Q8yJGqQMXea0DfP78ZSbeQmytHOUYeShaE
         qhjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=GvoO3wp6RPYKF7b9iCHiXewSex8mO3VSqB1Vp5KD6mA=;
        b=QgmrFgdhIMc94MJJLgA4FmFslrQuzV7hMGUU9KHXmVyUjhX8lJ8jwiTa8AnAmJPXI2
         zz9FTi8rhul+DeCjJu+9APGAqccPbn1oxMADIpH0Wrhvx2Kl39lYfmBzjFO3Tymq5vw+
         v8WwRSj8qCXCerhPdsOHHnYy4LRmNfUUjf2lNS4TP/tcISjBjnT8DxKRhCjGDlL00rZn
         1JsIYE85egh1i+cFtVKCC3ju+1JEl25L83t8Wee1BF/DGBVZIU2C8Expr7NNh9dq8T0e
         Jk+qE2V6nJiW3ntEewKcPqjQNzhVczbL639YYyHdpp6hi+nFZAz3QtZNxx3bdvZLq+af
         z6uA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
Received: from www262.sakura.ne.jp (www262.sakura.ne.jp. [202.181.97.72])
        by gmr-mx.google.com with ESMTPS id f184si568499ybg.3.2019.12.05.02.41.32
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 05 Dec 2019 02:41:32 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) client-ip=202.181.97.72;
Received: from fsav304.sakura.ne.jp (fsav304.sakura.ne.jp [153.120.85.135])
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTP id xB5AfI4B052654;
	Thu, 5 Dec 2019 19:41:18 +0900 (JST)
	(envelope-from penguin-kernel@i-love.sakura.ne.jp)
Received: from www262.sakura.ne.jp (202.181.97.72)
 by fsav304.sakura.ne.jp (F-Secure/fsigk_smtp/550/fsav304.sakura.ne.jp);
 Thu, 05 Dec 2019 19:41:18 +0900 (JST)
X-Virus-Status: clean(F-Secure/fsigk_smtp/550/fsav304.sakura.ne.jp)
Received: from [192.168.1.9] (softbank126040062084.bbtec.net [126.40.62.84])
	(authenticated bits=0)
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTPSA id xB5AfHTe052651
	(version=TLSv1.2 cipher=AES256-SHA bits=256 verify=NO);
	Thu, 5 Dec 2019 19:41:18 +0900 (JST)
	(envelope-from penguin-kernel@i-love.sakura.ne.jp)
Subject: Re: KASAN: slab-out-of-bounds Read in fbcon_get_font
To: Paolo Bonzini <pbonzini@redhat.com>, Dmitry Vyukov <dvyukov@google.com>
Cc: syzbot <syzbot+4455ca3b3291de891abc@syzkaller.appspotmail.com>,
        Andrey Ryabinin <aryabinin@virtuozzo.com>,
        Bartlomiej Zolnierkiewicz <b.zolnierkie@samsung.com>,
        Daniel Thompson <daniel.thompson@linaro.org>,
        Daniel Vetter <daniel.vetter@ffwll.ch>,
        DRI
 <dri-devel@lists.freedesktop.org>, ghalat@redhat.com,
        Gleb Natapov <gleb@kernel.org>, gwshan@linux.vnet.ibm.com,
        "H. Peter Anvin" <hpa@zytor.com>, James Morris <jmorris@namei.org>,
        kasan-dev <kasan-dev@googlegroups.com>, KVM list <kvm@vger.kernel.org>,
        Linux Fbdev development list <linux-fbdev@vger.kernel.org>,
        LKML <linux-kernel@vger.kernel.org>,
        linux-security-module <linux-security-module@vger.kernel.org>,
        Maarten Lankhorst <maarten.lankhorst@linux.intel.com>,
        Ingo Molnar <mingo@redhat.com>, Michael Ellerman <mpe@ellerman.id.au>,
        Russell Currey <ruscur@russell.cc>, Sam Ravnborg <sam@ravnborg.org>,
        "Serge E. Hallyn" <serge@hallyn.com>, stewart@linux.vnet.ibm.com,
        syzkaller-bugs <syzkaller-bugs@googlegroups.com>,
        Kentaro Takeda <takedakn@nttdata.co.jp>,
        Thomas Gleixner
 <tglx@linutronix.de>,
        the arch/x86 maintainers <x86@kernel.org>
References: <0000000000003e640e0598e7abc3@google.com>
 <41c082f5-5d22-d398-3bdd-3f4bf69d7ea3@redhat.com>
 <CACT4Y+bCHOCLYF+TW062n8+tqfK9vizaRvyjUXNPdneciq0Ahg@mail.gmail.com>
 <f4db22f2-53a3-68ed-0f85-9f4541530f5d@redhat.com>
From: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Message-ID: <397ad276-ee2b-3883-9ed4-b5b1a2f8cf67@i-love.sakura.ne.jp>
Date: Thu, 5 Dec 2019 19:41:18 +0900
User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.9.1
MIME-Version: 1.0
In-Reply-To: <f4db22f2-53a3-68ed-0f85-9f4541530f5d@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: penguin-kernel@i-love.sakura.ne.jp
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: best guess record for domain of penguin-kernel@i-love.sakura.ne.jp
 designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
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

On 2019/12/05 19:22, Paolo Bonzini wrote:
> Ah, and because the machine is a KVM guest, kvm_wait appears in a lot of
> backtrace and I get to share syzkaller's joy every time. :)
> 
> This bisect result is bogus, though Tetsuo found the bug anyway.
> Perhaps you can exclude commits that only touch architectures other than
> x86?
> 

It would be nice if coverage functionality can extract filenames in the source
code and supply the list of filenames as arguments for bisect operation.

Also, (unrelated but) it would be nice if we can have "make yes2modconfig"
target which converts CONFIG_FOO=y to CONFIG_FOO=m if FOO is tristate.
syzbot is testing kernel configs close to "make allyesconfig" but I want to
save kernel rebuild time by disabling unrelated functionality when manually
"debug printk()ing" kernels.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/397ad276-ee2b-3883-9ed4-b5b1a2f8cf67%40i-love.sakura.ne.jp.

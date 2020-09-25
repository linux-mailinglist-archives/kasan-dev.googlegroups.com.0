Return-Path: <kasan-dev+bncBDGPTM5BQUDRBSXKW35QKGQE4VVYTPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D6B42783BC
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 11:15:55 +0200 (CEST)
Received: by mail-io1-xd39.google.com with SMTP id e83sf1398709ioa.2
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 02:15:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601025354; cv=pass;
        d=google.com; s=arc-20160816;
        b=wVt+R9rst204pVwUAVpLmg1bye2GwUSFjI0KQ5kTjZlqtNhD87gbQTX020wHOaLC26
         qMGBokeKiPCNujAnFEksV9/KJChu4pzsTLjb+XnOksAdJRzCBLen7SnnG+Yis64P0X2d
         pWlQ0y+AGxkzJODBGqhZom1TmG4eq1jhw98trjN+1xZM0B17tGmtKUAi1hjnjSNbXw+/
         5ySW7bv1gs0+mbs9GAUwHIVBdVBO76WkNUwWnCNzy2CMehSWR0fRNveNEMKtHDtIghGL
         ivKxx2Bp6bGK68FpxaUV8JcpHX6tMB1pdiSLDzZD0VuxNFon+RuLbxk+D6M7Y/Xiy8at
         fBRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=VJbM2m2ffmNToShqn4DwsQdF2dangr/LEk21JdDzrRc=;
        b=BpsHPB2uo4I0mPdzVZtP7jPEAwQmzZrKLqhT2TDdeOE9QDHLZ90ODAZcF4rC1JCXYx
         AsalT5Flo6xNMH1S/hKVr9VUFIxq9JRoyd87SWPzADQXpLNQSfq02JU18z1Oq9nDoVof
         leqjziA0qdZQF3YffSlvpKmcmMb+gnFAJ3pIIDQGsaHH1UF+KzG4spFED1q1eGQlPcpr
         DVxDfMlK4PcQVyH0femzdHKI4nuvUngqk7nfzEYpuX0/Ys0muHV+1D7OUzRAIjfIHNJ7
         t9+YkBsSuUYrVcFPcuVUJRiArZTKP7LihWUHJ2LrOxALub+ZeC3NJBtJk10fzrm5chdh
         6waQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=MHPfO+56;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VJbM2m2ffmNToShqn4DwsQdF2dangr/LEk21JdDzrRc=;
        b=iVfiU8Qszxr+lbUdz79BLP4PyokltmXj9aEMdNcHqJuJjQqpt6Ten1R+2i5/cjL1cc
         EYSBE9k9JO+4sYuiGLhrBasCaa6/J41I8Pvz9sU3KICpK4t+tZ11+Fs0nuBbg6Ze2DCO
         3DNjOdXHj1ZiVD2tKwCqV2fv3SCmmxuQynu3BWytj8wk3/gm8iz9z+ynKXmgszGDgujk
         lVsfS55xRSzXqLciuGegnpi5RPTQysXhBzAwSY71nZ9WUgsTBrsQWjhFHhNRPckWzrDM
         DbbcxRAkYu+rnPXThGh0BvFQjWoVGs9LYgiZ/Gu4sRaLAXvP70mS1qWJfi6HjJAwK6Hs
         Qi2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VJbM2m2ffmNToShqn4DwsQdF2dangr/LEk21JdDzrRc=;
        b=dw6iBg44QokH4437SfS7fWZlpiwcIbzUTrjmMdf5KAnd8L/ofm5a9Q+lpEQwwCW46a
         7Vm0FKNOWEd+y932esnzsyoNYpAUJUSVN5SrAk6WuKdnoxxyDPbqwC8+0twgiJxomU6I
         9uQCkT7680F6Hl/m6qiI/Q54oS/fpmOIvSHkZvOjrndCr7tfcFNe3A/LgeBidjHB4FQ/
         c1E6g3LwqhnX8CtetlXH/jwXWaipSBll6AOhHoKcatpCzyUdjV5v9irlrKo36yiS63uj
         A+D8WjGXu/2k8z4ESyNeb93EQQ/VTfkfv5JEhl+oA8tLqxPZ30Rnzd9BRRGZiaE0TBZ2
         Fs5w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53157DTr7QpKFqignulot1wqQaYQ7rx6aH4LSaVHxhOy+vYqIPlY
	Bsn97/hwQpbfG6D53LqHZco=
X-Google-Smtp-Source: ABdhPJyzWc3/d/gaTdOsknwa2B684WBNtVf+Fwazwis8L5G6W+tXRe+ViMHsjrBOUWZmkQLBuKxWQQ==
X-Received: by 2002:a92:c504:: with SMTP id r4mr2379650ilg.201.1601025354505;
        Fri, 25 Sep 2020 02:15:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:6f56:: with SMTP id b22ls289830jae.9.gmail; Fri, 25 Sep
 2020 02:15:54 -0700 (PDT)
X-Received: by 2002:a05:6638:14c8:: with SMTP id l8mr2540261jak.136.1601025354091;
        Fri, 25 Sep 2020 02:15:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601025354; cv=none;
        d=google.com; s=arc-20160816;
        b=wZP6bxlMFiKtOgyiNON853pmZmI1cEJNzmpetuTdQHRM6RcPbcCo5yfHxqLervI6hE
         nPACYrwhHLPKgMlPLDQ7rFL/Fwi2UEW8yoZI0B/GewMK0xlJJTblSS2tpG3Y/Rw8pRjA
         K4x9CwzmxbszFir/SJaX4kMaceEaluOiF0hkFu3DkNYX1ra0fSKq8flnFoy+P9R1UUve
         MSlLlCylH1UVLGYQ/AZbTj3vqnRB9KKANxVhygxd3nSuRwjwwHJXH275AKVdo2RzPAaS
         dWUJyQuza43aVkiCmTWbGp7fSGvHdbXuRtqxYOvwGLF5W1sgq1OokQMhv/d4PnRb0tOD
         aVPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=wYZQKOZQHIfcecchTzNpFHCWhysG2MkETQF4DKJWtpw=;
        b=cnbjVJjxYculPmnGstAC2ysNGwfp4I77OfqB6rokC4AG6Dz4A8Ij2nJYAhJ1U/IWih
         CVZaNE71m71xc/8CIU97r0tjA61KKJ68ZKhc8xokW45q8PdkAQzDMx2V3WoltmMnWqVN
         YJfKjEA8wqo48VqxEsh4e+q9RnOiJFSWTPLYymdnM3MmWe6tuMRcwwH4Gutt/WvsUSEc
         yTkHWZweFiQkeRLd/wHZm7z9oown0Rrqq7ffjAQmd5ekf+vELFINhnGPA0jILdZwencA
         pyvCpsHwXbPNTX0Xx7R8H7TpukaxbHf6+59RDv4DR8svXK+/MPjVlVPru9WVxp34lNQd
         ukbg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=MHPfO+56;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id n86si129635ild.4.2020.09.25.02.15.53
        for <kasan-dev@googlegroups.com>;
        Fri, 25 Sep 2020 02:15:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: b377c338c36e441fa181cdb2e44b81ba-20200925
X-UUID: b377c338c36e441fa181cdb2e44b81ba-20200925
Received: from mtkcas07.mediatek.inc [(172.21.101.84)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 256298133; Fri, 25 Sep 2020 17:15:49 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Fri, 25 Sep 2020 17:15:45 +0800
Received: from [172.21.84.99] (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Fri, 25 Sep 2020 17:15:45 +0800
Message-ID: <1601025346.2255.2.camel@mtksdccf07>
Subject: Re: [PATCH v4 1/6] timer: kasan: record timer stack
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Thomas Gleixner <tglx@linutronix.de>
CC: Andrew Morton <akpm@linux-foundation.org>, John Stultz
	<john.stultz@linaro.org>, Stephen Boyd <sboyd@kernel.org>, Marco Elver
	<elver@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, "Alexander
 Potapenko" <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, "Andrey
 Konovalov" <andreyknvl@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>
Date: Fri, 25 Sep 2020 17:15:46 +0800
In-Reply-To: <87lfgyutf8.fsf@nanos.tec.linutronix.de>
References: <20200924040335.30934-1-walter-zh.wu@mediatek.com>
	 <87h7rm97js.fsf@nanos.tec.linutronix.de>
	 <1601018323.28162.4.camel@mtksdccf07>
	 <87lfgyutf8.fsf@nanos.tec.linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-TM-SNTS-SMTP: 226A7A570B87CE4811210E74AF646C2772ABB9F1C3FA85FE059A86BBF585F5742000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=MHPfO+56;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

On Fri, 2020-09-25 at 10:55 +0200, Thomas Gleixner wrote:
> Walter,
> 
> On Fri, Sep 25 2020 at 15:18, Walter Wu wrote:
> > On Thu, 2020-09-24 at 23:41 +0200, Thomas Gleixner wrote:
> >> > For timers it has turned out to be useful to record the stack trace
> >> > of the timer init call.
> >> 
> >> In which way? And what kind of bug does it catch which cannot be catched
> >> by existing debug mechanisms already?
> >> 
> > We only provide another debug mechanisms to debug use-after-free or
> > double-free, it can be displayed together in KASAN report and have a
> > chance to debug, and it doesn't need to enable existing debug mechanisms
> > at the same time. then it has a chance to resolve issue.
> 
> Again. KASAN can only cover UAF, but there are a dozen other ways to
> wreck the system with wrong usage of timers which can't be caught by
> KASAN.
> 
> >> > Because if the UAF root cause is in timer init, then user can see
> >> > KASAN report to get where it is registered and find out the root
> >> > cause.
> >> 
> >> What? If the UAF root cause is in timer init, then registering it after
> >> using it in that very same function is pretty pointless.
> >> 
> > See [1], the call stack shows UAF happen at dummy_timer(), it is the
> > callback function and set by timer_setup(), if KASAN report shows the
> > timer call stack, it should be useful for programmer.
> 
> The report you linked to has absolutely nothing to do with a timer
> related UAF. The timer callback calls kfree_skb() on something which is
> already freed. So the root cause of this is NOT in timer init as you
> claimed above. The timer callback is just exposing a problem in the URB
> management of this driver. IOW the recording of the timer init stack is
> completely useless for decoding this problem.
> 
> >> There is a lot of handwaving how useful this is, but TBH I don't see the
> >> value at all.
> >> 
> >> DEBUG_OBJECTS_TIMERS does a lot more than crashing on UAF. If KASAN
> >> provides additional value over DEBUG_OBJECTS_TIMERS then spell it out,
> >> but just saying that you don't need to enable DEBUG_OBJECTS_TIMERS is
> >> not making an argument for that change.
> >> 
> > We don't want to replace DEBUG_OBJECTS_TIMERS with this patches, only
> > hope to use low overhead(compare with DEBUG_OBJECTS_TIMERS) to debug
> 
> KASAN has lower overhead than DEBUG_OBJECTS_TIMERS? Maybe in a different
> universe.
> 

I mean KASAN + our patch vs KASAN + DEBUG_OBJECTS_TIMERS. The front one
have the information to the original caller and help to debug. It is
smaller overhead than the one behind.

> That said, I'm not opposed to the change per se, but without a sensible
> justification this is just pointless.
> 
> Sprinkling kasan_foo() all over the place and claiming it's useful
> without a valid example does not provide any value.
> 
> Quite the contrary it gives the completely wrong sense what KASAN can do
> and what not.
> 

I agree your saying, so that I need to find out a use case to explain to
you.

Thanks

Walter

> Thanks,
> 
>         tglx
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1601025346.2255.2.camel%40mtksdccf07.

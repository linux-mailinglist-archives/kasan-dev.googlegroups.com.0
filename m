Return-Path: <kasan-dev+bncBDAMN6NI5EERBZWI2L5QKGQEC6E3D6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id AD94327EC9A
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Sep 2020 17:29:42 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id l15sf757111wmh.9
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Sep 2020 08:29:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601479782; cv=pass;
        d=google.com; s=arc-20160816;
        b=Si3S6kZIxwF6SMXnKm28t2U5SfXEeaseAQXGOyAiJaR/z33/stWIE6CDUGQn/DdOrv
         nnP6eZ/3bubnPisEz2dVKyE/ZcOU2JbHbavstPTvBlxVfemiXuYOEFwmRFIkwnfpgZXx
         gv4j6AF7PC8/oMVqanLlLGmSxIeykFARVb7/VaZs1v7yOjPjN2D/VuSDfgEvP0kLr8Pj
         EaMK7KHXR3gde2rPwGsY6Rrh4B+X9rwXw4Y1HlsvxCYgceItt7VYKMcRUc3gGDcs1CzD
         QMOU4eDeoBU4Zdca4uorh4dbu7ZAi8arKx8fsxsP3twdVwfEKAk04OD1Qy1bSx3KLzHu
         Hk0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=hIpFL7pbd14btV0iLy8ZWfrqaoQSfz3CWn2n/vMkSqY=;
        b=CdS+P+/g276o/1NRQTlCVAcf94AV54dl3kTfi9z11eCmWw0BTYsqHI+tF+6C7gnHgA
         WwPh8L2L4YDE9GqSgDAApKL7zpzwdOn0rbNRZ99VWDsVNixxi+ixiH3jsxQTtnvZAWj5
         nx5/B01m6FBiayr8cFfc+TAhR4h0IlUkscmBt8QEaJUAX3VCyPINq+BqcwPOqu7YfG5j
         auktxEZDo1S28s2yvzosu8FcDKSCAJNJouhqausSzjDj9ODPFURPlmxrDvEw3vHmUV/9
         auz/jpH33kfC6qFk/WJCCvGUSpwVofZGPvc7a2/3TOZ20G+j0p7vD5EWXluS1AzY2qcd
         jvng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=fC9bWFoE;
       dkim=neutral (no key) header.i=@linutronix.de header.b=WRJ8lzbK;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hIpFL7pbd14btV0iLy8ZWfrqaoQSfz3CWn2n/vMkSqY=;
        b=NAIxVvVRwJBbMj73KTFealiGEcAtewfNkkuMs0pFqpOAuKuRVIU2Zmy35Z9CS6Qe1y
         lnTKj07ay9Vv/AMjTGkRJ9xmNYSWDN2jEIm+GQnmUJguEtXrB1reUED2Zhjp+7UXDOlJ
         Bdlhur/UQIDwcPppMZcfIQ4mNsQW9Tj+vOM9MRUFPUV5IhwO3zoxU22H1oTwygksDcCU
         4RU2rXZxSTgJ4cgDcmw+6fPhoyAeY2KbFbKrSsQFcvaupivFRMbRwP13A7Jtvx6waLmk
         pq8f1UDwDXhvYHb44onHtZrKdeVsewHwlgbxnUijyrNMzRvBsWMyjCOZN/3//iGPFiJl
         0/KQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hIpFL7pbd14btV0iLy8ZWfrqaoQSfz3CWn2n/vMkSqY=;
        b=b0mITXPeDuO2R3CYhd4Av1Lnbk5OIiq+Gf9FNPJY09kfYQenUTmtLgrZ0L5xt5qac1
         RYog3q8vLrCqfRF8OT/hQvOwToMq1Ppj9ZVTR7Ods5aKXukkAh/iPxO50cYdu/hyY6+K
         z6ng0dbPO66uX+m40TK2Gb9eUcd5TkN7Mvzxe7XS1e3QlGOiqaHoIqR8ut0jGYfiCaVQ
         VXWJ2iqq5rW+uA37pwtqdlKy0wbw3P6KYJ2geJCZncch5OmpdANoFA68C35kGdT2wwUz
         /k4v5UWBcEFEvkpYLqmV73SdZtIBqOc2PmNe1ka0cH/9UoCENfTIM7FzANQppChpsV1R
         DOjw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530zQB54dq8h5XyH9SGRHH8rbgWF2f5QwQrSGwRmMl/JESThOCAg
	D1UHKdJPdZvvwRexhtkXM+s=
X-Google-Smtp-Source: ABdhPJwqmIF/DRMnW6t32XZwwsEdPMUhZzleVDNey4yePopBUxp+N+hEM4EwdUMxPHXU+Itcse2NWg==
X-Received: by 2002:a1c:2d86:: with SMTP id t128mr3844611wmt.189.1601479782359;
        Wed, 30 Sep 2020 08:29:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:8:: with SMTP id h8ls931462wrx.3.gmail; Wed, 30 Sep
 2020 08:29:41 -0700 (PDT)
X-Received: by 2002:a05:6000:100c:: with SMTP id a12mr3997749wrx.115.1601479781504;
        Wed, 30 Sep 2020 08:29:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601479781; cv=none;
        d=google.com; s=arc-20160816;
        b=dM75qXPyQOdIIR5ily3e7z9HZjEyA/elAp4Rs8xVONLl/ucZYqmWCD4HzzaD1RVV46
         bf23ZmHWw8+JtcAHCouTgay+wLeok+uC5nuv5STHSEljlxZkSMHAOfQJWH6YMDZbaV2S
         hj9d1oXlO5MQWD+4zLwvagVb3+plhVCqIjnWpVViHw/++3sFV0hEoSwBS8K2p4cKTiB+
         6sosrCNIcOPv9NXn79n00DFm7J3eitWQaG7fneRSra1oaP9Ign3nKOiscgiFY1Oofqye
         DHotRnJr0XMOYxRqmjoofPbQvCPd53B2RpntOJdazg8BHTdBdnzuTlMWKb873V7f+FyG
         DKaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=aqZau5xYcLfz7fU6kWPWcUxXzOYMn4YTVPKLqoPQKaY=;
        b=Xv0ZI++Nw1EbjmfoLJ6mGSBPhCMKsUNBo1WvvV0B1vSabIe0Z1yYcVC0cLYbsbzzQr
         kpsVZBDDq3JXh0NsKFBAEKr1NN9nb3lzBgNSFkKa++1Bu2atau7fScmG7DjylV+flupJ
         mHbQ4r1rPwYcINwGuwp3g4C4ICg/jwNSsU3NKzFNHxmI161a5NlOqYGVyaxcXh6IDwmA
         yVNt5LKtyidGLsjvncyKfyq4jonC3vxMdK42ImjqTg+Y8zBWSUko9Tt+H+5Pr7mUrFF3
         RdXCEGgFfYfKWTCWkeXeQH+5fLHR7NW62tRKvoR/iPQ8HqzM7z/vpZWxUu0Pn5dVWGGd
         4OXA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=fC9bWFoE;
       dkim=neutral (no key) header.i=@linutronix.de header.b=WRJ8lzbK;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id b80si13518wme.1.2020.09.30.08.29.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 30 Sep 2020 08:29:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Thomas Gleixner <tglx@linutronix.de>
To: Walter Wu <walter-zh.wu@mediatek.com>, Andrew Morton <akpm@linux-foundation.org>, John Stultz <john.stultz@linaro.org>, Stephen Boyd <sboyd@kernel.org>, Tejun Heo <tj@kernel.org>, Lai Jiangshan <jiangshanlai@gmail.com>, Marco Elver <elver@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@google.com>, Matthias Brugger <matthias.bgg@gmail.com>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org, Walter Wu <walter-zh.wu@mediatek.com>
Subject: Re: [PATCH v4 0/6] kasan: add workqueue and timer stack for generic KASAN
In-Reply-To: <20200924040152.30851-1-walter-zh.wu@mediatek.com>
References: <20200924040152.30851-1-walter-zh.wu@mediatek.com>
Date: Wed, 30 Sep 2020 17:29:40 +0200
Message-ID: <87h7rfi8pn.fsf@nanos.tec.linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=fC9bWFoE;       dkim=neutral
 (no key) header.i=@linutronix.de header.b=WRJ8lzbK;       spf=pass
 (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1
 as permitted sender) smtp.mailfrom=tglx@linutronix.de;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

On Thu, Sep 24 2020 at 12:01, Walter Wu wrote:
> Syzbot reports many UAF issues for workqueue or timer, see [1] and [2].
> In some of these access/allocation happened in process_one_work(),
> we see the free stack is useless in KASAN report, it doesn't help
> programmers to solve UAF on workqueue. The same may stand for times.
>
> This patchset improves KASAN reports by making them to have workqueue
> queueing stack and timer stack information. It is useful for programmers
> to solve use-after-free or double-free memory issue.
>
> Generic KASAN also records the last two workqueue and timer stacks and
> prints them in KASAN report. It is only suitable for generic KASAN.
>
> [1]https://groups.google.com/g/syzkaller-bugs/search?q=%22use-after-free%22+process_one_work
> [2]https://groups.google.com/g/syzkaller-bugs/search?q=%22use-after-free%22%20expire_timers

How are these links useful for people who do not have a gurgle account?


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87h7rfi8pn.fsf%40nanos.tec.linutronix.de.

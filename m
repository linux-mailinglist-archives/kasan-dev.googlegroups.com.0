Return-Path: <kasan-dev+bncBDAMN6NI5EERBCNFWT5QKGQE24GR4HY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 7324A277B2D
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 23:41:31 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id j75sf42125lfj.7
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 14:41:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600983690; cv=pass;
        d=google.com; s=arc-20160816;
        b=wTyVRiNBcewJH/IoJuAN47SMCqTsNGIk+MvP33AdL7v2fNdjuqj9+r2A+LDrVO88s5
         2b+IHQm1uF1Fmz1I9wbJFKehbDi7+Yh+ICJnGYWH10MqsDT6nHH/b6CbTdrKxrMe4och
         qu7/Oi5WrP4Zty2Y3NehQdmYRRU4pjoVQCLmot3TS3CMJ2t+Sczc/ds3SUof3KJEsUKy
         B6vnCp/FilI0egFekN4M+y3ArWOv8ZtIW5WerLT8uwJdNgtfnYeXCqqh5peHhdAxciwK
         afiH1ir9fIn6InsM+rLre4EPuSTsmp5JmMSvgx3rPKMESrf6aBQZReU5vFYbjqC4fS93
         8T5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=/Yv9PlnfokZKyzGLjYszmVZ+fBR/W7JYxXv1Upk2pMo=;
        b=qrvqCb2E6/RGxzSUdzgkzHdaY6Fhru2o7G9yUKi8LIYWeWyuWIJVsJtbX9oJRsgT/N
         VMsE5k6QZxKwRyS3EUq8fGzjw9WyHRIoCQ5lahDvyPtg3wCyBCCnpdGCRmdc36fE9LFz
         rqpq8uEn1CHpV1Pei7OlpPY0cjJb2qqjVxPS+uOW68gWtZdTSU/9s1gcPrczsivk8O2U
         RVq8bd8MqPdQPS6h/0aTlsZPJToBqW3wDlG18URoH/OH3ajLIiJqhPuG8OYZvj7RLDz8
         2OoPSsg/jZ6Sctaym8HVYXNRr5xGcoOWQxH03st2EXes8UhV1Wyd/uakRf+rWbWf+GOU
         Ic6Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=s9aB8dgH;
       dkim=neutral (no key) header.i=@linutronix.de header.b=vCvDhw1z;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/Yv9PlnfokZKyzGLjYszmVZ+fBR/W7JYxXv1Upk2pMo=;
        b=cwFZZ7OkTtpppmCXXYHVYzfc3PAaFQ0CAmfv9W2fFWZbi3MEk/SGMicnp0ATvebHd3
         +9rssGKmu8GrpufFhYxTOjSqryP3Wc9QgYtQMqs/jVkVBijSd6LR1WXYnatqC+qyRM2R
         YcxtfZqoudRNrfO+WGvs5l67RcLFZwkcitJVL7OB864EVOroh0Q0Ss0S6xazlSYVlRS4
         /wnQqX7Rt4GAqzMVdLPhdJmZlgs41a9JNRTIpWYID5bWEsRl3klL5taGNpaE7GttBtcY
         LPula7ax517e0R5KQ3IN3dJkJdG45i1zxAbljuXMTjI+CslJDZqQ8UlWDy0t4PaU7l4V
         aYoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/Yv9PlnfokZKyzGLjYszmVZ+fBR/W7JYxXv1Upk2pMo=;
        b=gOjR3ehnmRuU58DhngH1bEzL2A2cb3anIjSOxAGmyKma4BY57SDqPngbrKW8E7gct7
         tJwB17SUNtFv0iASpeFJcbEhLJxdN7MjoiSIz22oLePfmeH7twbITU+qhvac0EDp8VN0
         kygNTmQME4aH+YL+2oozMEQLdBz/d5Fls1g7YQuBYQwfaA0wE+yGtlkQmnd1gy/x2KM8
         NWuEa1/oKymOyNAUwp7nI6YmrH30I9kXdp2NK2vy4Q1HgZ3GC0JLhKq3Rriy/xhYlVYz
         BThO2TlZyzDHO/Aou0EXE4nP+k83uFGHrZKQuetWv82tWCs7HLuW4yYLUH4odZkfaWe5
         N8XQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533X9OI3dCjXBONlRMyGYyvlH1oUaHzU0zz02WBQzPy7QnzggGuE
	W35bS2xupFDG94eI8SFtdNY=
X-Google-Smtp-Source: ABdhPJw7X1KT1AR8oh5Y3RaDoJLxV/szGBXiF4Why7GSnnjLFIid38O+NN+6jPXkGJTcJLLU3I35Iw==
X-Received: by 2002:a2e:9c8d:: with SMTP id x13mr298134lji.392.1600983689935;
        Thu, 24 Sep 2020 14:41:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a556:: with SMTP id e22ls72756ljn.9.gmail; Thu, 24 Sep
 2020 14:41:28 -0700 (PDT)
X-Received: by 2002:a2e:98d1:: with SMTP id s17mr307885ljj.188.1600983688783;
        Thu, 24 Sep 2020 14:41:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600983688; cv=none;
        d=google.com; s=arc-20160816;
        b=gagfpWBbCnLjRVtcsWxp4rwUzaDfbDOx4Vsr35R0XwP7q1ZClIAXZ86vA4Ha2jt2Mw
         +b8Hr2dEHkf+Pyui/HbPq2RvXMowbmbetbPxX66qHw3dWl9CYzMaowC7F4T4wlk7HL3u
         94Vlvi08lV07r4lNRhTCAtjFT9gX7v1T5Chl9oAXHQyShsDIS0OR+a7BIkNil2kHXZ+o
         PBcYaZ6NnWXHbrWHNTCppPwSufLkQvoYRsC/gi29tu1Zd02Pq4LdpkQ1aBwN6rhpVDgE
         BWvggU8ZNXEkrLn962YEl29/KxSs2csUhUWGNIyJ5imi3FoKMZY/Jt1OYvDRqKO08g71
         cKDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=PH7EM+jC9sAvN+hNyU7Ecq4szctd2TEmbXpjLXpwHLk=;
        b=oRaL92wonfSnuRw9QRmohaTQQ/UoaoUqzZ6JwGaHxb9T8fTUlWH3HbMtRkfqjzFxzO
         /dK6ZkOvKkfZxpZdEk1wumm4hjoL2GmHkgVeHJT4501atkqua8Pc4JIJOrESL7dvJxFw
         7aC8zt2mTlUwndYUW43kypLyGBMAjrpXGAX1YGtkZOf3IA0QDNs+wSKaKIjWAFQC0BH3
         D61xl5leRZNfG5wJHtXnKgrYwCJtrjrulD5jezEv91+GFvstYgNuPH7eeCwc0csKH7eo
         5km7YBL5CPTQKgjysl1cTct7e39Pnz1lKI3+IQazRPir1W/ykEEPLdraWfbCSP4G8eQe
         RcGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=s9aB8dgH;
       dkim=neutral (no key) header.i=@linutronix.de header.b=vCvDhw1z;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id z6si17336lfe.8.2020.09.24.14.41.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 24 Sep 2020 14:41:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Thomas Gleixner <tglx@linutronix.de>
To: Walter Wu <walter-zh.wu@mediatek.com>, Andrew Morton <akpm@linux-foundation.org>, John Stultz <john.stultz@linaro.org>, Stephen Boyd <sboyd@kernel.org>, Marco Elver <elver@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@google.com>, Matthias Brugger <matthias.bgg@gmail.com>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org, Walter Wu <walter-zh.wu@mediatek.com>
Subject: Re: [PATCH v4 1/6] timer: kasan: record timer stack
In-Reply-To: <20200924040335.30934-1-walter-zh.wu@mediatek.com>
References: <20200924040335.30934-1-walter-zh.wu@mediatek.com>
Date: Thu, 24 Sep 2020 23:41:27 +0200
Message-ID: <87h7rm97js.fsf@nanos.tec.linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=s9aB8dgH;       dkim=neutral
 (no key) header.i=@linutronix.de header.b=vCvDhw1z;       spf=pass
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

On Thu, Sep 24 2020 at 12:03, Walter Wu wrote:
> When analyze use-after-free or double-free issue, recording the timer
> stacks is helpful to preserve usage history which potentially gives
> a hint about the affected code.
>
> Record the most recent two timer init calls in KASAN which are printed
> on failure in the KASAN report.
>
> For timers it has turned out to be useful to record the stack trace
> of the timer init call.

In which way? And what kind of bug does it catch which cannot be catched
by existing debug mechanisms already?

> Because if the UAF root cause is in timer init, then user can see
> KASAN report to get where it is registered and find out the root
> cause.

What? If the UAF root cause is in timer init, then registering it after
using it in that very same function is pretty pointless.

> It don't need to enable DEBUG_OBJECTS_TIMERS, but they have a chance
> to find out the root cause.

There is a lot of handwaving how useful this is, but TBH I don't see the
value at all.

DEBUG_OBJECTS_TIMERS does a lot more than crashing on UAF. If KASAN
provides additional value over DEBUG_OBJECTS_TIMERS then spell it out,
but just saying that you don't need to enable DEBUG_OBJECTS_TIMERS is
not making an argument for that change.

Try again please.

Thanks,

        tglx

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87h7rm97js.fsf%40nanos.tec.linutronix.de.

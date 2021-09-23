Return-Path: <kasan-dev+bncBCT4XGV33UIBBDM3WSFAMGQEJ3HCO6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id B034F41687D
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Sep 2021 01:28:14 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id p14-20020a92d48e000000b0022cf3231b41sf7226563ilg.16
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 16:28:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632439693; cv=pass;
        d=google.com; s=arc-20160816;
        b=P2e3veDbnKJ0fcBVW3y6In971LTY2myrkO26ErRQI/+GT+yIePDspgj9ALYD1mK1g0
         mqCWN9HLmjAYWPojQKtP+JRgSw3QvVZMnNlwZS3xiz8R3dZQoCV6a3arKXO/jfb8hA7q
         bvEsrW6L4HmJhLZWOFT/dcvqeDyVREEAAwcY1xBUyeGVyNf0bjzkmsi4viiakyUDmblr
         7s7N5RP0sF8xjSIjO7c4DV3VbG0cOFvBRxE1xIW614+h3enjlfq24Uzz0zVC8oKKbc0q
         +tgDmuIFQiQA9rq2WY5gGKh8beFf5cPRV+rDx9RgywyOa8KduMYadGjcjx9N5nhVRp8V
         yxag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=Llc7VWMdl9N5Vyp7NU54wm912wrtofZPr7K5KZZPOyo=;
        b=x5GqXopMtllKaq7pIVr16NOj1JomhAiplvQeyNl8WDANstsqVSjx+OvDy9x9/lEgKf
         UKK2ZuG6mTBNTA0DmYalEKvmvguZ/TqOu9sIJCUET/pPtI7ySEHVXCFfYPwsVEL0XkOP
         hhzj5PIm0KB61OEuFiViTv44I23SzcPeMe1nbCoilwQqL8afxd081kqEeoEJyrRw7Mcn
         j69qpey3tQA3+f0sPWmCA/+/keG2MBzDzB5nkly+aXTUbHEtK97FbCg0gl3+xQGl3vSc
         1sAeVGhzFmh3tqcHsjhdzsWUlOhdshvQJS7DAtAet7qqQibBeUCBO73A5+OL71kNAca4
         Alww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=QoqOFG2q;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Llc7VWMdl9N5Vyp7NU54wm912wrtofZPr7K5KZZPOyo=;
        b=C3Nhrz4FnIACbAhUiP8rREQ/O1f2JeMcFnJEJ54Gw7Vw+b8y77Wv6k8Df/p8myIylg
         luZwvn44LWZLrdI6wr5KBTycYjIlXCqaOVLQAvG+NKlHJni3IkTkNJaIWCUTvXpqZ5UC
         Vb/dwXZLYdhzKT3zKTc1VFvg3FGwKyTfDSfdKEhB+3/wDmrunXhOh6UHAM7JHnY5bZmL
         h/10Kesfmw82MEOPuTtAKx7oFd42z92yv2jMETPOGCSCXcGovMF/518XOM4N3OhBZF95
         BOr6HU/jjnxqet7M5KfK16Jj9IMWgDtOIeCPrIs/HsZli7T4ZojVdpaCEybOtaPRul2x
         xTig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Llc7VWMdl9N5Vyp7NU54wm912wrtofZPr7K5KZZPOyo=;
        b=MyPybPxyZvx/mfHMlRz2THc+M3TOeBWeh6E9NC7TH2BNb0NdZFxasJi0FSMhTYKzX7
         MLykiM3hgtPa4+Z/vnSBnPyA8jnUR0UP7DHyLth7FtqGjUaxe1Yz9CwQcq0bXdwPSLc/
         kuyFqnbRpET2Cx2uz32Sw1nO5r+JIkTWHJCbCcnKC/QSQZie/EDifrDw3BDXOuyu5N4E
         QYlkyqPljj6AxdKLv0UJUIGkPuJk55H3FdH/L1qtEML+YaKFjdCf02ZiUW3GI58vCwsS
         H2NJVWb/jH+2SJZ3Twfy9vSBXwICxbf+e1QF0cyHnS9W64SALdbXTAfO9h6h8+hmyzPq
         pVbw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532sZcjozMkDFuD2z0tiDf+OjzzGf2JaD/rmJjj2Km0aseWKMiIU
	5BSrBXX/Ehuh0/2MWed7RwU=
X-Google-Smtp-Source: ABdhPJyn4EJPVWehDujn41KTE9oSiQ8J8TuAjMy5+fC2oa1Zar6WO8zr7z/YqI6F7bAo9wgWfY6RFw==
X-Received: by 2002:a05:6e02:1c24:: with SMTP id m4mr5829726ilh.296.1632439693710;
        Thu, 23 Sep 2021 16:28:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:f906:: with SMTP id j6ls1489119iog.9.gmail; Thu, 23 Sep
 2021 16:28:13 -0700 (PDT)
X-Received: by 2002:a05:6602:1a:: with SMTP id b26mr6199834ioa.0.1632439693307;
        Thu, 23 Sep 2021 16:28:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632439693; cv=none;
        d=google.com; s=arc-20160816;
        b=Zr51RV4/c4MAevDcKaK+AZL864uFoY4S3F5hLBWIFv+bOELPsqDlgfZKcswQqY77ys
         9oImAhtaa8ZFu4SZnMMxN5bwi++/Y57oXvWjWxL9CXNFOcWz3pYUCYKuphrVFQmCCMcH
         o+bPRLy79FxY2scE/HMiRZr40IRohcTrVAF26vYkHE1r/AxsruLhiV4tPX523jA4JnwH
         GwQVGmjNLkvFjmhULCRuWDOR98AVCUj7fGw3w9zGs2kB0x2qTW2sgbD+KiXTD0TZxwuz
         fC2MhmWqbnYzE2my2HWgd9pmkHCsIQTbtgO6S06g4PIGB4n7pkCjDzyAgzJg+abFwWra
         OvcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=UoYtoTmstwML8ZYwPoyxeKRDOk9ZLn4Jb/LikJefzXM=;
        b=x+X9PyH3MTggRx9Wnvj6VaEXl2Nv6lf2lgG3sQSKmyG3myF9X3YdvMiCBFaCPdtbca
         nSOk8/5zzDu3xFAfEOcanbEZesRqSHinwBvoSySTtZJ8QRV5VP1JFOe/ZbDcHzRut09I
         KBMaAKkghB+phH7MllJYe0sw0ngTOwxtV521lnppERhk6U6/DIFZ1ejSVk2g3WQNg8MT
         TNQlI+sQnH90xd55gLABFmQf+vxLuSyRKByNMrSej7WM1r3w/e6CH79ByaZjLqYaBJLh
         aQ22YDgCYf0OP4tmdr8tU710LV83ZByX/gn8KWGzmnQg4nRbBmvhZaIaZUNyBFtM9BWG
         zfTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=QoqOFG2q;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id l68si513894iof.1.2021.09.23.16.28.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 23 Sep 2021 16:28:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 60AC760F43;
	Thu, 23 Sep 2021 23:28:12 +0000 (UTC)
Date: Thu, 23 Sep 2021 16:28:11 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, Jann Horn <jannh@google.com>, Aleksandr Nogikh
 <nogikh@google.com>, Taras Madan <tarasmadan@google.com>, LKML
 <linux-kernel@vger.kernel.org>, Linux Memory Management List
 <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH v3 4/5] kfence: limit currently covered allocations when
 pool nearly full
Message-Id: <20210923162811.3cc8188d6a30d9eed2375468@linux-foundation.org>
In-Reply-To: <CANpmjNOh0ugPq90cVRPAbR-6qr=Q4CsQ_R1Qxk_Bi4TocgwUQA@mail.gmail.com>
References: <20210923104803.2620285-1-elver@google.com>
	<20210923104803.2620285-4-elver@google.com>
	<CACT4Y+Zvm4dXQY2tCuypso9aU97_6U2dLhfg2NNA8GTvcQoCLQ@mail.gmail.com>
	<CAG_fn=V31jEBeEVh0H2+uPAd2AhV9y6hYJmcP0P_i05UJ+MiTg@mail.gmail.com>
	<CANpmjNOh0ugPq90cVRPAbR-6qr=Q4CsQ_R1Qxk_Bi4TocgwUQA@mail.gmail.com>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.31; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=QoqOFG2q;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Thu, 23 Sep 2021 15:44:10 +0200 Marco Elver <elver@google.com> wrote:

> > > > + * time, the below parameters provide a probablity of 0.02-0.33 for false
> > > > + * positive hits respectively:
> > > > + *
> > > > + *     P(alloc_traces) = (1 - e^(-HNUM * (alloc_traces / SIZE)) ^ HNUM
> > > > + */
> > > > +#define ALLOC_COVERED_HNUM     2
> > > > +#define ALLOC_COVERED_SIZE     (1 << (const_ilog2(CONFIG_KFENCE_NUM_OBJECTS) + 2))
> > > > +#define ALLOC_COVERED_HNEXT(h) (1664525 * (h) + 1013904223)
> >
> > Unless we are planning to change these primes, can you use
> > next_pseudo_random32() instead?
> 
> I'm worried about next_pseudo_random32() changing their implementation
> to longer be deterministic or change in other ways that break our
> usecase. In this case we want pseudorandomness, but we're not
> implementing a PRNG.
> 
> Open-coding the constants (given they are from "Numerical Recipes") is
> more reliable and doesn't introduce unwanted reliance on
> next_pseudo_random32()'s behaviour.

Perhaps we could summarize this in an additional comment?

Also, this:

+static u32 get_alloc_stack_hash(unsigned long *stack_entries, size_t num_entries)
+{
+	/* Some randomness across reboots / different machines. */
+	u32 seed = (u32)((unsigned long)__kfence_pool >> (BITS_PER_LONG - 32));

seems a bit weak.  Would it be better to seed this at boot time with
a randomish number?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210923162811.3cc8188d6a30d9eed2375468%40linux-foundation.org.

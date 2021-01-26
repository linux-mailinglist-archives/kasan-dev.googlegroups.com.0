Return-Path: <kasan-dev+bncBCJZRXGY5YJBBKVYYGAAMGQECCE6N6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93f.google.com (mail-ua1-x93f.google.com [IPv6:2607:f8b0:4864:20::93f])
	by mail.lfdr.de (Postfix) with ESMTPS id C90D7304614
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Jan 2021 19:15:07 +0100 (CET)
Received: by mail-ua1-x93f.google.com with SMTP id o16sf6402266uaj.10
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Jan 2021 10:15:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611684906; cv=pass;
        d=google.com; s=arc-20160816;
        b=ypYBwCs3rZ+sm5JNU8W2XTMElLAP7myLIr0lQCKuajKvyBe5ZWlQTT/0H+TVLUcHiq
         zYzDSLHYm5VeWLDdcR7XmZU/dYYWTVhGEtBmuH8Uiw8+dOKWW9tltBFN0uaGmaRMaZwx
         DiyDiPq826YZXuBMBtvsiwxYnAknKNezBpHW1nYrtR9luSRF0FyQOujVwDbLZSbj/BU/
         lbnKs4p8/FCTjoG/VzJm3xMTu0z44OuIYjIttoW2QKp7ulsdXXQb4hNuqCbSCunGaB2/
         Sz/Xs3ClcnXc7aiNWxQ/tnIUsL4DNL2hrpqPQfv+GftFD+igeocLcZ2cJA/NIhBJpB9Q
         pxLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=fF918rRaYXYcyDhLqeFm4YzIBnMOFLFGWtFMJPCC89k=;
        b=0OvhiGaQ+HlSl1CDTkOn0bVUBsElP6q5M6lftIgPrQvEDK4wagklVwAKjwfUXdPxaj
         opclA3AYuqTynezzo/1kH0jO2Y3Kdtr+ZbHL4ump4r900RiV7OhLHzrs42VqPoUF636U
         B+DuFKW7I8I0JU1Gf97Y/S1jGXkq5QqknSWkbBB6ex6pg5YRQUVGH2VfZtEHdER2xGGh
         De9+mEb4vHRG3kG/88eo6Vfyz0Job5N9VdBsDIKVYi9JNbchHV3DGvd/HARPPzHrq19p
         njxPvVUvmemRaIICc5ZZn4uiSm4ZOVbveYBJPbvSkXIUoY0bUujSuQ9+10ehvWb6/Rfr
         DfBA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=KJ8iYIzf;
       spf=pass (google.com: domain of srs0=4sgz=g5=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=4SgZ=G5=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fF918rRaYXYcyDhLqeFm4YzIBnMOFLFGWtFMJPCC89k=;
        b=V3kkMjGSHjtPHvzEtLERwgXbMcSXTpktauTuZzmWAbeT0UpfvAodmeew1SLreDlOKg
         9faEOwIFm987+VUX0q0qL2wm64eMAx25PkQVzc/G9NdykzZyQbLZB/6GM8rnLI5RVr8v
         bllTN3/U79UbEr+x+pc9xsGNRiXJtenprFQzGdCyxChOkhbc7wmg3j3MqOoN4Jtz+J4t
         67sl66K58rTXcUiqv44s4NOtAIZiiPLkdoTfAvMXZI4YDmWKfmQPYbs8swz5v8nlRQjz
         5firNA7hgmxFWlSqM74n6OZYcAi/j4Cx5ybVzkPNh1lINZp9GkXUBe6gvGuWF1TyJi12
         NbRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fF918rRaYXYcyDhLqeFm4YzIBnMOFLFGWtFMJPCC89k=;
        b=nfuJ0w1i4RYBR+tAN9lADKDg0wK5g0n5CUiiSPtpVHOv7osXTBXOnQFLk9xb2Ir9Wi
         f/XUtuwEfnIgJoqeAO7J0rklFHif3a6zFlxelOXHjG8YM3zuK8qR7/G8NBV0OiZeosP+
         nYJW81lxW1Xl6NLP6GZV4w4XzABqQyMkrBgamTsCM5dFf7xnSmA7YJstAuBGw+UkWIe5
         7ijU3wZl7MhAyNLdI/W3lgPgUM9AnUPxtDYFKVh7If82pj0ukOB6CwG3yFT0HCnPR7fb
         U1GBADWAuRJPFUlixjjw0gpJv3u5AobsDqko3q7qLYdyXxWq3z1kD/kUDRuwK0ipWPli
         VDNQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531+t8h1kWb2qb8zvuuXZHtqI3IfsbOcUDLeqH6ZS3HCeNgDYErF
	+/8NUB/pwVTkgNjDJQz0Hyw=
X-Google-Smtp-Source: ABdhPJwp/pV9tY/RPI6TJqEKJi6A0nA7WzWgksxIe+EIWnlPXD2CpDNLxe/cFNKISfRx6JNtdSJM5g==
X-Received: by 2002:ab0:2502:: with SMTP id j2mr5550298uan.0.1611684906709;
        Tue, 26 Jan 2021 10:15:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:b409:: with SMTP id d9ls939541vkf.9.gmail; Tue, 26 Jan
 2021 10:15:06 -0800 (PST)
X-Received: by 2002:a1f:4dc3:: with SMTP id a186mr5996722vkb.18.1611684906035;
        Tue, 26 Jan 2021 10:15:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611684906; cv=none;
        d=google.com; s=arc-20160816;
        b=o+fYZxRWsdihILVZVR9yxPrcGR6CYmz2mvNCXlWNyXuGzR+yRWDq6meZD7H3ttd+Hz
         sDU7Ghal9t5WzJVLubrRluSi3guweezlBmzXxVsqesP+aqN1sh+Ud9eP984WnTb/OCj8
         9hnFTWPT8k4rSPnDyDOmYpuEKeM7FVLDvdypmbZyoJ8Z/HzRfvdjMh1trv4luIW2pSdJ
         WYmyOYVJ+gfm/Ux7Uk+uuEETGilSxaeOR1uOVfuoQsOcfURpsrSg+9O66Ymzjymgf4BQ
         Ws2MqXAHbHJ5s9P7dfQ80W0HkOyyzYtD1ks2JayhP556jpVRGdgjm4a8csTPEQsORAo+
         qaww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=i+1t76Z1dNFXpM4wBzXIU2NbjwAOLlBoa8GnB//cnD0=;
        b=dA3eacEN/jbTxWaXQ3oqKzmCpKb3MPn1XSPAgCGtFAY7BZKUVjnwuiElzLs7qremdK
         BMEWmuVmERAjsW0japJU0wOhYjTeWyRpRY70Kci4xiPmErOe8zKeaTRYhXWL2My2WmqH
         qk5nqwhc/FQdn2xNxByImgO1fF3MjQ0VdwlzcGiy8ooZTaZHPWnisQEhohA+RWJA+Sbl
         EMh6pTobtUhWxQX1uVYOJovF+sz8AplnQKZrtMe+oLUWHEw/Tpr4Zqw2q+ciFMfzKW83
         vVFM0xQEsskrriRQ1+C/DelWifqK12jqOe/U1li0dj0B8t9vv7r5sbhkASK6wFpSyrTU
         Q9tg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=KJ8iYIzf;
       spf=pass (google.com: domain of srs0=4sgz=g5=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=4SgZ=G5=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id d25si930515vsk.2.2021.01.26.10.15.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 26 Jan 2021 10:15:06 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=4sgz=g5=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id EE5E820780;
	Tue, 26 Jan 2021 18:15:04 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 9617C352268C; Tue, 26 Jan 2021 10:15:04 -0800 (PST)
Date: Tue, 26 Jan 2021 10:15:04 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: David Gow <davidgow@google.com>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	boqun.feng@gmail.com, kasan-dev <kasan-dev@googlegroups.com>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH 2/2] kcsan: Switch to KUNIT_CASE_PARAM for parameterized
 tests
Message-ID: <20210126181504.GF2743@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20210113160557.1801480-1-elver@google.com>
 <20210113160557.1801480-2-elver@google.com>
 <CABVgOS=sOZ29Q0Ut8YSKD+BrXDQwGftPeYEoON_iOxajK_wL9w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CABVgOS=sOZ29Q0Ut8YSKD+BrXDQwGftPeYEoON_iOxajK_wL9w@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=KJ8iYIzf;       spf=pass
 (google.com: domain of srs0=4sgz=g5=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=4SgZ=G5=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Tue, Jan 26, 2021 at 12:35:47PM +0800, David Gow wrote:
> On Thu, Jan 14, 2021 at 12:06 AM Marco Elver <elver@google.com> wrote:
> >
> > Since KUnit now support parameterized tests via KUNIT_CASE_PARAM, update
> > KCSAN's test to switch to it for parameterized tests. This simplifies
> > parameterized tests and gets rid of the "parameters in case name"
> > workaround (hack).
> >
> > At the same time, we can increase the maximum number of threads used,
> > because on systems with too few CPUs, KUnit allows us to now stop at the
> > maximum useful threads and not unnecessarily execute redundant test
> > cases with (the same) limited threads as had been the case before.
> >
> > Cc: David Gow <davidgow@google.com>
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> 
> Thanks! This looks great from the KUnit point of view: I'm
> particularly excited to see a use of the parameterised test generator
> that's not just reading from an array.
> 
> I tested this as well, and it all seemed to work fine for me.
> 
> Reviewed-by: David Gow <davidgow@google.com>

I applied both Reviewed-by tags, thank you!

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210126181504.GF2743%40paulmck-ThinkPad-P72.

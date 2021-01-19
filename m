Return-Path: <kasan-dev+bncBDV37XP3XYDRB3VPTOAAMGQE55RSN5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 912C22FB62B
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 14:00:32 +0100 (CET)
Received: by mail-qv1-xf37.google.com with SMTP id i20sf19577235qvk.18
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 05:00:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611061230; cv=pass;
        d=google.com; s=arc-20160816;
        b=n0a9DlANnCARMx4GKufu7XEJbD4eiAEGNWIn/CjMnCYxPCD9RgnZhe/7841WkT6CuF
         NXMk/BFY2UNVbhu40iHooE8mgNdCgwUEl1mHgBhD03JrWzka4q3oOWxHmPEX0kERPgsu
         dFgPy0yhrLANevXF1CgQ0d4vBNKNfjOfn+Anx9gucjd2fznQ0C3IqJJzCz4fgbuMFHW4
         sFuNVd0xpznvj3y+k89XotnEClDnuI/RiN7birZjSS/vvLQGd1xXI/kecGgvsK+CrDP3
         HixSTw7l2Nn4G6yhmqbMBW7Esyi7LuB6wRl0/FXUT/UQTDxr0hgDtBiXxQfXSp1SoqZd
         qbWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=cX8qkj+Mv1PheEcIZtKA44XkDqAZQRPzq6D5o2ZBkVI=;
        b=I50TzMpzcptK+d7YFyTaVoPCUsyIavIlYSrs7T1rI+V0q0BNhVQfpn1RE5YIxbCl8O
         JLr28+PXdwni51Wv2SNEpb3xEqW8mg65hiO+FxopGjaoEMPhPpRTlLOdj7fUf6c5+7gk
         +nMX74E6dHcny/E+Y5O58b7MG9DaSOTLHqAEMIc/wqF0tYLWLP5F1GfSQ6ehYql2UAtb
         nHv6A9hz8rnJLITZVKPc7PVok6AY0svV3fRc/kZarFlAGK5OX4gUqUW1o0iQMqtQ/mN+
         CO+w2PKWbOsgzOo2nNQIdQsJXjBr5bx0IZLlniGl8I1uEoGD0oDq31jRmERpsc3KVAQ/
         USWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cX8qkj+Mv1PheEcIZtKA44XkDqAZQRPzq6D5o2ZBkVI=;
        b=rykazTIbNKTNRIxkGX4QfKzFLq3KVZvAn+mrNVVoilGlqdX8L16mwB2KfheUaVLkkv
         EQbaRG08Ij+23GfNLH/Itqm98tcWVqp7LoFZyDk0K/gX1P52dh7uleHIqXEgIXqu9KSD
         sul+67rOHmrJj323N4VvZRAqVZsIKLpKyWyOdpLaUoerQxIeSmzU6mXUrkugTUrEup/S
         m2/x4uLXYmizXvE+RJZgG53bpwXUKx7mZDyGZlPJ42LeyunuU4hSOygPSs1zugEoG6eq
         6dARMTy8Jk1tYX/V6H8TnhK0KePcoH5Bl1rYoU6m1gpbgvDvkm9Q6nJ4UN4JYMmhy+zn
         O5Xw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=cX8qkj+Mv1PheEcIZtKA44XkDqAZQRPzq6D5o2ZBkVI=;
        b=NfMIVoUnL2TK9gC7HeTe27tPvMjxVhaAE1rLO3GRKqKNCrwvD7QMC0bIvgKJadqoMI
         02EqJW0ZlL3PcFRnK/zRdMdIRsEAaxzYNJsI30qEQ42ASISRjE7HO24IPQLG1gv3cPOb
         Eiq/dkAd0MnAO979H8OD3ps8/pU3MVy1164x+qgFqn0V3eBp6+lRUTxMR8zeBU3YvmX8
         YFmUJ9RxJYPfmi6hmjUxbUrdvty1fcOVEwp/m3+PHVA7DWq3oRPVa8w6aZOvChL8nfyK
         9WNkxVXUk/TZwAWxoyyaE5vbegiErlNN04kFgXX9wJmjGKUMNy/0FTgpMuZnsQdBjaBk
         aqbQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531e/JiBcT9JXUtRB2+v9p1qJzdeeXfSw2kd8R1gb1enTM5K62N/
	eGM4eUiluseoX7uqJ6BWcaQ=
X-Google-Smtp-Source: ABdhPJzMQJb01jchii6+a7te4Ih6U9fc1jO3zmQQg23VkI4ePksMLixJ29KDXejndxVudTITg/OIwg==
X-Received: by 2002:a0c:f48a:: with SMTP id i10mr3933682qvm.61.1611061230528;
        Tue, 19 Jan 2021 05:00:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:221a:: with SMTP id o26ls1035861qto.3.gmail; Tue, 19 Jan
 2021 05:00:28 -0800 (PST)
X-Received: by 2002:ac8:57ca:: with SMTP id w10mr4005632qta.12.1611061228784;
        Tue, 19 Jan 2021 05:00:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611061228; cv=none;
        d=google.com; s=arc-20160816;
        b=I36AzbOxftdDS+hGopKnd3ibj/E1dmEAw1o/rHPdUXVxAk6nGfx6psV3yP5btLyqhe
         5qiHMZT4vJ1oNXh7jbawOe0cEnWgYZy4ZpAcIobECNqqTqI9YqwydppbflOtD8yuirpY
         xDLcTTJa8UKy0gR7/v3PVtqETXag2nMp243fMH053Wj4PlkmsImGnGdgJ024U5yBT2AH
         ITBTVujFWaU+36aZzIjtsF30mdenBphTTpRFOSPdRB6NZ4SXRZ5w+Ag47QbjbrAQpC2q
         uybWiEUOTajY92ZiMqHIJB8E/scZFkxJLo8NUWCA5pt1/7IOiqe/WQzSt18gaRSrFBCb
         fI5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=60F55+Ny3T9vurauT+3CuuJDBJgGd2o+Y1SdXbm1KMQ=;
        b=xeg6Uf2RSJpGL+ZSDzmKq5e8qD1X/Pk+Tongen5eg++YQjfxBceYnnBQGxDiNC3FdD
         FbxI5x8kxc0wYJ3XHF6mzx2rWoprp13xxq9pkIgZDKgxnQfqlwW3ofTubgZw1F17Gc9l
         Hw4UUcjO+7w+clxr7ugUhwUT/p7hhturUOYYaTejnzGkWzVNXa8o8TZHVk1Yv1kyMIWN
         o+Tfzxa/yZOdrht2GVzC03+XoTrmILeiPWQmr+6uPPxufZlt/rBJkz6YDK5ODzv1YVQp
         VC0k98EfRGoY2Gl6iohy+EA2AIoR0lFd3RbabBDcnWNXDmEGfm6N1DbgOB0RdQlv7Xvb
         enCg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id z25si2267678qth.3.2021.01.19.05.00.28;
        Tue, 19 Jan 2021 05:00:28 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id D35BE113E;
	Tue, 19 Jan 2021 05:00:27 -0800 (PST)
Received: from C02TD0UTHF1T.local (unknown [10.57.41.13])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id DBC7F3F719;
	Tue, 19 Jan 2021 05:00:25 -0800 (PST)
Date: Tue, 19 Jan 2021 13:00:10 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: 'Dmitry Vyukov' via syzkaller <syzkaller@googlegroups.com>
Cc: Russell King - ARM Linux <linux@armlinux.org.uk>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linus Walleij <linus.walleij@linaro.org>,
	Hailong Liu <liu.hailong6@zte.com.cn>,
	Arnd Bergmann <arnd@arndb.de>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Krzysztof Kozlowski <krzk@kernel.org>
Subject: Re: Arm + KASAN + syzbot
Message-ID: <20210119130010.GA2338@C02TD0UTHF1T.local>
References: <CACT4Y+bRe2tUzKaB_nvy6MreatTSFxogOM7ENpaje7ZbVj6T2g@mail.gmail.com>
 <20210119100355.GA21435@C02TD0UTHF1T.local>
 <CACT4Y+aPPz-gf2VyZ6cXLeeajLyrWQi66xyr2aA8ZCS1ZruTSg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+aPPz-gf2VyZ6cXLeeajLyrWQi66xyr2aA8ZCS1ZruTSg@mail.gmail.com>
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

On Tue, Jan 19, 2021 at 11:34:33AM +0100, 'Dmitry Vyukov' via syzkaller wrote:
> On Tue, Jan 19, 2021 at 11:04 AM Mark Rutland <mark.rutland@arm.com> wrote:
> > On Mon, Jan 18, 2021 at 05:31:36PM +0100, 'Dmitry Vyukov' via syzkaller wrote:
> > It might be best to use `-machine virt` here instead; that way QEMU
> > won't need to emulate any of the real vexpress HW, and the kernel won't
> > need to waste any time poking it.
> 
> Hi Mark,
> 
> The whole point of setting up an Arm instance is getting as much
> coverage we can't get on x86_64 instances as possible. The instance
> will use qemu emulation (extremely slow) and limited capacity.
> I see some drivers and associated hardware support as one of the main
> such areas. That's why I tried to use vexpress-a15. And it boots
> without KASAN, so presumably it can be used in general.

Fair enough.

I had assumed that your first aim would to cover the arch code shared
across all arm platforms, to flush out any big/common problems first,
for which the virt platform is a good start, and has worked quite well
for arm64.

[...]

> > > 3. CONFIG_KCOV does not seem to fully work.
> > > It seems to work except for when the kernel crashes, and that's the
> > > most interesting scenario for us. When the kernel crashes for other
> > > reasons, crash handlers re-crashe in KCOV making all crashes
> > > unactionable and indistinguishable.
> > > Here are some samples (search for __sanitizer_cov_trace):
> > > https://gist.githubusercontent.com/dvyukov/c8a7ff1c00a5223c5143fd90073f5bc4/raw/c0f4ac7fd7faad7253843584fed8620ac6006338/gistfile1.txt
> >
> > Most of those are all small offsets from 0, which suggests an offset is
> > being added to a NULL pointer somewhere, which I suspect means
> > task_struct::kcov_area is NULL. We could hack-in a check for that, and
> > see if that's the case (though I can't see how from a quick scan of the
> > kcov code).
> 
> My first guess would be is that current itself if NULL.

I think if that were to happen (which'd imply corruption of thread_info)
the fault handling and logging would also blow up, so I suspect this
isn't the case. 

Do you have a reelvant vmlinux to hand? With that we could figure out
which access is faulting, how the address is being generated, and where
the bogus address is coming from, without having to guess. :)

> Accesses to current->kcov* are well tested on other arches, including
> using KCOV in interrupts, etc.

While that's generally true, architectures differ in a number of ways
that can affect this (e.g. how the vmalloc area is faulted, what
precisely is preemptible/interruptible), and we had to make preparatory
changes to make KCOV work on arm even though it was working perfectly
fine on arm64 and x86_64, e.g.

* c9484b986ef03492 ("kcov: ensure irq code sees a valid area")
* dc55daff9040a90a ("kcov: prefault the kcov_area")
* 0ed557aa813922f6 ("sched/core / kcov: avoid kcov_area during task switch")

... so I don't think we can rule out the possibility of a latent issue
here, even if we haven't triggered it elsewhere.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210119130010.GA2338%40C02TD0UTHF1T.local.

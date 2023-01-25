Return-Path: <kasan-dev+bncBC7OD3FKWUERBPF3YWPAMGQEXZCW6JI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id A00DC67B73D
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 17:50:05 +0100 (CET)
Received: by mail-yb1-xb3d.google.com with SMTP id p19-20020a25d813000000b0080b78270db5sf3202633ybg.15
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 08:50:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674665404; cv=pass;
        d=google.com; s=arc-20160816;
        b=v6a2rlt3MQUQ5+2s8yKPec/WE4jcqStp3SIS9WGpDT4txS6lwXtGujrf/aSx8WL6E1
         qSreASKOLMkIamxt4MXuhph00ToubzblKHRYm2Y/I2qVpDTJ5k3+t4SuC7akv1a8xDxU
         inOd0bpcFJ0XjDdbgSYuFJ7z9cKr4O58KdBx0F1CJmNKQ3qJCj3+BBOcK0NZeuJDoEW0
         8bD4oUpAlnu4ZEVPP8DhFx3BCly+JlKTX0qOtiXvnUpJztp77o+HeiirDkgpA0miK1ev
         A3nsC5dmD0LVYxawvOWTijVBeSEDK/3gd/gp28Na0ZOciV869A3DM3nGaCLjO9dbnFWt
         YB2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+Cj5itwI8VlVsLa2VqRNEptTmsae06e2O+Z346iOUKU=;
        b=t12i1SeLmoFQTH6N4DDTzUoljT0NISuWsZNuV/VM6lYqdHLcVUAYNzyPehrWdoGIqs
         pa9UrrZQdFSUZppPq2xteNeQ5WgWw8OPbdHsoPsp9gN1qs6JDaPSmzY/opCG5NLXs1Sc
         6T01NO/4DOl8VsFsZuOVMFrMjwoaUqUyYx0M2atXlIqr8oe45W9PwUXLr1VJCofw78Bc
         MiDu4014WYaXCvhKJvmECap2ALBJBcb1Tmqs2jzU5CajObjXjdIQVFDb0uoDmBlblAkw
         EKnMKOXAbh6hpGYOgcwkgeU45Xjx+xeJyjeuICHOinmeV6gwfiYtyFoq+qMx3YENrr7A
         w7rg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=telMSbME;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1129 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+Cj5itwI8VlVsLa2VqRNEptTmsae06e2O+Z346iOUKU=;
        b=EyDkw2djcASkho3uqRgk/0oHNzO1r7/BDUfw+QXwjnqM/2kywzABjTj/PuGDTqH6z/
         4NsOekY8/QE6TdBtB1gnTqtoeD9FAx9hTJJu4MYeydk1sa11nhZrJLBhpvXl9Xt7ugx4
         3seO6srUgrg9KcJ5K/bKyfNGYu/sSBKLTAH0zsRIRTQAbWzqoCK+E1vSFJlFLb7tGXFK
         Zxe+kyB1TTjfNb0GQtviN4s30nz0bUBlfbH5kncRAC0lJp61oF4i1PoqQc4EY9TRAz9J
         wIyUu23TdodIVEZfRfvh0nQOLoXmBUu9NnHZe/0aZY6f28r5K8MHwtnIHxZiZwfnI7Tl
         S6EQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=+Cj5itwI8VlVsLa2VqRNEptTmsae06e2O+Z346iOUKU=;
        b=dd3dJBxpMiK+/HIfG4lQDGfCqt1Z/XetsCQAC26vuW7UeFAlTfBnNQzaLX0A+0bLJ7
         p3//TgZFGOKk4FLmmAyYEjVnbzh7RFUbe7F1FzlsThgoJPMc3nLGhDvmYfbGbSVHsAIw
         pGjMP1P3HEo533Nhe7jx8MEoNn/CdeBBHoNacAyxXY0qFw6hCX4LOR4BfSU0Da5IfXh/
         iyBxWOfDJWfx6JlxnL9YK3a6NlrcarGWastjQEK/veyduMRQD3PN8sxd4rrF8cSq+DNu
         dMLgvBPOKqZGdk7Dxj0YPrgAZhYsN4jmfHvubXHQLIxJoPatU3TMAIOvfxyMhaDyHhnM
         q0Hw==
X-Gm-Message-State: AO0yUKXM4CVJzqMQsnr2rX3tBspbwugsSOP3dEFzZhrhtLu1cZvsIGZw
	CFP+MVJqvZp3yHDDe/l08cA=
X-Google-Smtp-Source: AK7set+TJcglv7tAkfcw4N7zGFWmOPZh5y5It+3qAZzeb6zzcul7OgAXTuaRJaGW9/wTj8+MBE34IA==
X-Received: by 2002:a25:6994:0:b0:80b:81e6:e96b with SMTP id e142-20020a256994000000b0080b81e6e96bmr555502ybc.595.1674665404385;
        Wed, 25 Jan 2023 08:50:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:cf4e:0:b0:80b:753f:3399 with SMTP id f75-20020a25cf4e000000b0080b753f3399ls3106395ybg.4.-pod-prod-gmail;
 Wed, 25 Jan 2023 08:50:03 -0800 (PST)
X-Received: by 2002:a25:ce12:0:b0:7d3:76ac:f07a with SMTP id x18-20020a25ce12000000b007d376acf07amr25525346ybe.2.1674665403796;
        Wed, 25 Jan 2023 08:50:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674665403; cv=none;
        d=google.com; s=arc-20160816;
        b=hhDl1kNRIuPyqVtpCzZup6SSfvGbenqkyjebgAgobdrQ9Hh9tJt9SAJEKS969DXe5z
         rVOPctJE/GTYTBNgQuAh1HywvLG4IsfPogR2MrJ0rXO5dNYYIDH7KlbxgoATE8JL85Lz
         ZhrUrPFiLwNWFgJiNNwkrm78iboXCHuybBIQJ9orYgeIrxT99b97YdtFoSXOHLAjATP8
         PMK/K2VuHmPh7i4TcLpkVfqAokMUReVT4UYR9NqN95olHOiEz125nJOb06C2zl8R/PUB
         oh2XYC3zUny5t73gUw4njSNI3WxtXj8Ta7OUc/qFON1QDtQO0oPX87Az4yYi+wOg8tBA
         ROtQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9oBkpwDuDP6Raat/HRHsNpx8MqzIjjZSJojQEumXoyE=;
        b=rloXoJXK7opemq3Pak1jUxcz6dDT+dp36GmoQF67927sjf7cHgXaFDUGaLDzrMIuH0
         Cp8+XBNNIqDeIi0vfxx4Mi6ea8znfluHZpL0b/sBxrg7QIJnIIUCb0JFXGrLJBRAJecW
         fL2k03TXWXL51kdC5J3qFyojD2nYN1u/lxwPXokqdIGEeNw+hKQcxwZnnxmIPeg/32qz
         r1Ulgvn5MkPnNShtq15l4XRPDsVS5k9lQvECrRB1SA5iEX3HbPbWFW6EywOw1dBnQ9D2
         qn1dR9QOLmTQWgVX+lH8LWsv0SFJ2sJmwjEqVyhkccxI/vSoURomJ/k5bbuv7krMELYm
         WNmg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=telMSbME;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1129 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1129.google.com (mail-yw1-x1129.google.com. [2607:f8b0:4864:20::1129])
        by gmr-mx.google.com with ESMTPS id h9-20020a25d009000000b008032606ec55si641640ybg.0.2023.01.25.08.50.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Jan 2023 08:50:03 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1129 as permitted sender) client-ip=2607:f8b0:4864:20::1129;
Received: by mail-yw1-x1129.google.com with SMTP id 00721157ae682-4c24993965eso271855207b3.12
        for <kasan-dev@googlegroups.com>; Wed, 25 Jan 2023 08:50:03 -0800 (PST)
X-Received: by 2002:a81:1d2:0:b0:433:f1c0:3f1c with SMTP id
 201-20020a8101d2000000b00433f1c03f1cmr4401576ywb.438.1674665403087; Wed, 25
 Jan 2023 08:50:03 -0800 (PST)
MIME-Version: 1.0
References: <20230125083851.27759-1-surenb@google.com> <20230125083851.27759-2-surenb@google.com>
 <Y9Dx0cPXF2yoLwww@hirez.programming.kicks-ass.net>
In-Reply-To: <Y9Dx0cPXF2yoLwww@hirez.programming.kicks-ass.net>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 25 Jan 2023 08:49:50 -0800
Message-ID: <CAJuCfpEcVCZaCGzc-Wim25eaV5e6YG1YJAAdKwZ6JHViB0z8aw@mail.gmail.com>
Subject: Re: [PATCH v2 1/6] mm: introduce vma->vm_flags modifier functions
To: Peter Zijlstra <peterz@infradead.org>
Cc: akpm@linux-foundation.org, michel@lespinasse.org, jglisse@google.com, 
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org, 
	mgorman@techsingularity.net, dave@stgolabs.net, willy@infradead.org, 
	liam.howlett@oracle.com, ldufour@linux.ibm.com, paulmck@kernel.org, 
	luto@kernel.org, songliubraving@fb.com, peterx@redhat.com, david@redhat.com, 
	dhowells@redhat.com, hughd@google.com, bigeasy@linutronix.de, 
	kent.overstreet@linux.dev, punit.agrawal@bytedance.com, lstoakes@gmail.com, 
	peterjung1337@gmail.com, rientjes@google.com, axelrasmussen@google.com, 
	joelaf@google.com, minchan@google.com, jannh@google.com, shakeelb@google.com, 
	tatashin@google.com, edumazet@google.com, gthelen@google.com, 
	gurua@google.com, arjunroy@google.com, soheil@google.com, 
	hughlynch@google.com, leewalsh@google.com, posk@google.com, will@kernel.org, 
	aneesh.kumar@linux.ibm.com, npiggin@gmail.com, chenhuacai@kernel.org, 
	tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, 
	dave.hansen@linux.intel.com, richard@nod.at, anton.ivanov@cambridgegreys.com, 
	johannes@sipsolutions.net, qianweili@huawei.com, wangzhou1@hisilicon.com, 
	herbert@gondor.apana.org.au, davem@davemloft.net, vkoul@kernel.org, 
	airlied@gmail.com, daniel@ffwll.ch, maarten.lankhorst@linux.intel.com, 
	mripard@kernel.org, tzimmermann@suse.de, l.stach@pengutronix.de, 
	krzysztof.kozlowski@linaro.org, patrik.r.jakobsson@gmail.com, 
	matthias.bgg@gmail.com, robdclark@gmail.com, quic_abhinavk@quicinc.com, 
	dmitry.baryshkov@linaro.org, tomba@kernel.org, hjc@rock-chips.com, 
	heiko@sntech.de, ray.huang@amd.com, kraxel@redhat.com, sre@kernel.org, 
	mcoquelin.stm32@gmail.com, alexandre.torgue@foss.st.com, tfiga@chromium.org, 
	m.szyprowski@samsung.com, mchehab@kernel.org, dimitri.sivanich@hpe.com, 
	zhangfei.gao@linaro.org, jejb@linux.ibm.com, martin.petersen@oracle.com, 
	dgilbert@interlog.com, hdegoede@redhat.com, mst@redhat.com, 
	jasowang@redhat.com, alex.williamson@redhat.com, deller@gmx.de, 
	jayalk@intworks.biz, viro@zeniv.linux.org.uk, nico@fluxnic.net, 
	xiang@kernel.org, chao@kernel.org, tytso@mit.edu, adilger.kernel@dilger.ca, 
	miklos@szeredi.hu, mike.kravetz@oracle.com, muchun.song@linux.dev, 
	bhe@redhat.com, andrii@kernel.org, yoshfuji@linux-ipv6.org, 
	dsahern@kernel.org, kuba@kernel.org, pabeni@redhat.com, perex@perex.cz, 
	tiwai@suse.com, haojian.zhuang@gmail.com, robert.jarzmik@free.fr, 
	linux-mm@kvack.org, linux-arm-kernel@lists.infradead.org, 
	linuxppc-dev@lists.ozlabs.org, x86@kernel.org, linux-kernel@vger.kernel.org, 
	linux-graphics-maintainer@vmware.com, linux-ia64@vger.kernel.org, 
	linux-arch@vger.kernel.org, loongarch@lists.linux.dev, kvm@vger.kernel.org, 
	linux-s390@vger.kernel.org, linux-sgx@vger.kernel.org, 
	linux-um@lists.infradead.org, linux-acpi@vger.kernel.org, 
	linux-crypto@vger.kernel.org, nvdimm@lists.linux.dev, 
	dmaengine@vger.kernel.org, amd-gfx@lists.freedesktop.org, 
	dri-devel@lists.freedesktop.org, etnaviv@lists.freedesktop.org, 
	linux-samsung-soc@vger.kernel.org, intel-gfx@lists.freedesktop.org, 
	linux-mediatek@lists.infradead.org, linux-arm-msm@vger.kernel.org, 
	freedreno@lists.freedesktop.org, linux-rockchip@lists.infradead.org, 
	linux-tegra@vger.kernel.org, virtualization@lists.linux-foundation.org, 
	xen-devel@lists.xenproject.org, linux-stm32@st-md-mailman.stormreply.com, 
	linux-rdma@vger.kernel.org, linux-media@vger.kernel.org, 
	linux-accelerators@lists.ozlabs.org, sparclinux@vger.kernel.org, 
	linux-scsi@vger.kernel.org, linux-staging@lists.linux.dev, 
	target-devel@vger.kernel.org, linux-usb@vger.kernel.org, 
	netdev@vger.kernel.org, linux-fbdev@vger.kernel.org, linux-aio@kvack.org, 
	linux-fsdevel@vger.kernel.org, linux-erofs@lists.ozlabs.org, 
	linux-ext4@vger.kernel.org, devel@lists.orangefs.org, 
	kexec@lists.infradead.org, linux-xfs@vger.kernel.org, bpf@vger.kernel.org, 
	linux-perf-users@vger.kernel.org, kasan-dev@googlegroups.com, 
	selinux@vger.kernel.org, alsa-devel@alsa-project.org, kernel-team@android.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=telMSbME;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1129
 as permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

On Wed, Jan 25, 2023 at 1:10 AM Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Wed, Jan 25, 2023 at 12:38:46AM -0800, Suren Baghdasaryan wrote:
>
> > diff --git a/include/linux/mm_types.h b/include/linux/mm_types.h
> > index 2d6d790d9bed..6c7c70bf50dd 100644
> > --- a/include/linux/mm_types.h
> > +++ b/include/linux/mm_types.h
> > @@ -491,7 +491,13 @@ struct vm_area_struct {
> >        * See vmf_insert_mixed_prot() for discussion.
> >        */
> >       pgprot_t vm_page_prot;
> > -     unsigned long vm_flags;         /* Flags, see mm.h. */
> > +
> > +     /*
> > +      * Flags, see mm.h.
> > +      * WARNING! Do not modify directly.
> > +      * Use {init|reset|set|clear|mod}_vm_flags() functions instead.
> > +      */
> > +     unsigned long vm_flags;
>
> We have __private and ACCESS_PRIVATE() to help with enforcing this.

Thanks for pointing this out, Peter! I guess for that I'll need to
convert all read accesses and provide get_vm_flags() too? That will
cause some additional churt (a quick search shows 801 hits over 248
files) but maybe it's worth it? I think Michal suggested that too in
another patch. Should I do that while we are at it?

>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJuCfpEcVCZaCGzc-Wim25eaV5e6YG1YJAAdKwZ6JHViB0z8aw%40mail.gmail.com.

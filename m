Return-Path: <kasan-dev+bncBCMIZB7QWENRBDM2UOLQMGQE2J44DVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id EB4DD58777B
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Aug 2022 09:06:54 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id z1-20020a0565120c0100b0048ab2910b13sf4114115lfu.23
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Aug 2022 00:06:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1659424014; cv=pass;
        d=google.com; s=arc-20160816;
        b=NEF8okZiNFYFeVPSPBc10eLfu2ouk2Zi87+7DzKQFBe83PdIjdUahHnjFBQc3Z/PEG
         S6Taa4pRmzB39nZMtT19zUsRuZymLM0hVWV7gI8VLGJtP0fD9kMs6qrf32DQIdqW1y9V
         Tve+1T/3IoFD2nfLthu0wxDf6NUhVsEpizM2ykiq3FRmSAYYu8JOg9QJfJDyZ+Ixja0q
         kIjNcnxACx1gjLNthfPV9YQExjnCwYl0FE0e5PuHauzPRi9Sohov5vUr/iC8GJfnUi4p
         j3zabce1TsjohWnUCDd526zsKK26AdjTQI/3/+IKcT/TNAG0Wx6roLGaNdwSYwDV6ot3
         Jrgg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=91Q9zUR+qc2rbHL5fAvLT8CbhyHHrRYXTHP1QUJGOF0=;
        b=YV7ORemVe/wO0018TyVfgmdT+9cp6wq628T5jCt8QCIjM3WYbbHv5tkqE/lXwahMV6
         cwha+cfAKA6zX4rnkIVxyFjrLzcn2EpsBZN0xK8Lg9fcgwQB92MU3pSitijB9YXoVYvr
         TvGp6utSYgOOErnRoGQ8Uj3fwH2vNcMOXw+FTCL1kdj7b3qub0sgorf5qKMUOhOuqrio
         guUvVD03KzBCLo9DPxhn/CJLQKh2vqleU7RdhtaHmxBUzPbGZrpu35jRaabJoGDRjezA
         esIiE+pyHNWnKMGLBfH3CH1oh0hK0xaKUPDmaX02Bu6J3KBJAicUa8aBl5HDsqC6oDjy
         UAhQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=gHKO1or5;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::236 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=91Q9zUR+qc2rbHL5fAvLT8CbhyHHrRYXTHP1QUJGOF0=;
        b=YK2RATd1tDOUEbSYnttHsZzAZ5GJ3Ti0uAiuXDeiY4wDkBolt2It7intw/qxXoUs3T
         T+YSSVzs/3+jw6DMFKNIl0cZMpf3Kx6DmjbMjqFGQuOuwq/AzAGNfMb7PuviOFmp7/OF
         +V0d+LAimyXXkGoQU0FlnKLF9lWXKzRUespJiuFMllzAarZ28dAGPtPM6BPc66kI7bCt
         ZarazHl4hKbx2waGl5nVwxl+Ttz3iO8sPRcfhxRkpG35MoiKu3o7HIcGgrl5iKudN//z
         bOsqsfNfx9j9t5DEj2olb2Ie2mdiXF39AuSzytb8TebVjp/sB7pra7V3k+AqVtBFxbt1
         uJyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=91Q9zUR+qc2rbHL5fAvLT8CbhyHHrRYXTHP1QUJGOF0=;
        b=e/67byxhUh3WU6Ltgtapt9UbuUNLQNUY+NpIXEL3twWl8de9JKS/U1/eFYVSRmRwLr
         1buhNqOOpwpUSl1OCLjz+eRb2333zKDOevM9A5BegXaYxnnyT/Z+XyonBqwgBHtJhSuE
         v/vaI6XYrrn1H76u0lRCsSvwI5gDKfzQUzpmy4iMxBuOEX13IgLmTt/kwFnukqN4VT5L
         L6lq+YHvSIJ9Dns5TFL1aob9OYzA1RVXwkCbwqT6QBXnagcpSSC3yLE3nlgWq5/mvMur
         iLVSHbY6cbSGmX1bUUPN7Pzso9JbRsd+s+Q23bkB9XFw08WhOVU8zSwd+KKvYBBU7D5L
         OSog==
X-Gm-Message-State: AJIora/LPcAfH8bdcXRsCaF7i4UK6PretCGP8QnTbMonx88w1NeswxPW
	G79JAKs/6bWRlP94yXK6IsE=
X-Google-Smtp-Source: AGRyM1uz8xI2XCp2O0Am1Q6XLqH0vFeyrj3Ss2iPB4UtzwrzDfBdVuZ3LFH0v+hywctVKl4AlQLGfg==
X-Received: by 2002:a2e:a7c8:0:b0:25e:200a:74cf with SMTP id x8-20020a2ea7c8000000b0025e200a74cfmr6637444ljp.271.1659424014224;
        Tue, 02 Aug 2022 00:06:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:3506:0:b0:25e:4169:af19 with SMTP id z6-20020a2e3506000000b0025e4169af19ls1519770ljz.11.-pod-prod-gmail;
 Tue, 02 Aug 2022 00:06:53 -0700 (PDT)
X-Received: by 2002:a2e:9cd8:0:b0:25e:ec:237c with SMTP id g24-20020a2e9cd8000000b0025e00ec237cmr6173223ljj.277.1659424013088;
        Tue, 02 Aug 2022 00:06:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1659424013; cv=none;
        d=google.com; s=arc-20160816;
        b=tHzYXr9CRRXvQhaEiKQSiFCEWZa9KpL+OTP6Mjm2bThKIK2aZIDWs+3pv7Kj/BTSYz
         9f4H673twKMxvcoIM6Xvgpnr/yYJy0xdak7dsExjOVI5zmb2agn1x3gaYFryT3B3sJnj
         km0EcJzENtqdpWa67hriUc+ngiW6/SjSaukQ6fxDH/OPtlNZtGQ4nyZ1iJ3Tj2y1D1cY
         MSyUixlrijuvDKMTZjr9cmwgR0HybUpUoGD4hMRsK1+3Jdbp2hJxxsK15T07V6LnmDHr
         4EsswBafHZ/8j2tN0hhIV4o9phnRk7/TYPj1EdWZ+SciOGTM+uQSliBwM7AxppVVxZHr
         Pbzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6vKqhsUzixhYOBMktOXVTY43Yh0tm2BA/2sZ3OGVl9Q=;
        b=CZ0sWOfNAkKswPOW2MlxHwXiosetKnmHGtDUF09c9uawsYy8qLDKr3pZkyJP4QT7Ub
         9EdBQwTnQSD3xfRgnVEwzARnV6vG8UEkZrGfISitS8mqHfh5zU+rjtRCr4nUlQ7ObslM
         V7JHUOp+uqv/FHBPmy7xNcgxCJgYlBKDwWbMV4a+X9whu1Yuv7EXkxK+4c8I2CfhyBk7
         rre0WzjonykXldZ2AtKIPIkPM0R0V3Pu2vbhaOzyLzj9FjzgrTh/zJaiqG9Odzj1khTH
         z78vxCoj3Yhyeb3dwjbgu+E7OeUXfTmHLX+OvNLmYcujFb9flBbx/uNsYaEo9nCHm/DZ
         7g0w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=gHKO1or5;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::236 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x236.google.com (mail-lj1-x236.google.com. [2a00:1450:4864:20::236])
        by gmr-mx.google.com with ESMTPS id u9-20020a05651220c900b0048a9b517b75si496806lfr.1.2022.08.02.00.06.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Aug 2022 00:06:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::236 as permitted sender) client-ip=2a00:1450:4864:20::236;
Received: by mail-lj1-x236.google.com with SMTP id m9so14643906ljp.9
        for <kasan-dev@googlegroups.com>; Tue, 02 Aug 2022 00:06:53 -0700 (PDT)
X-Received: by 2002:a2e:bd0e:0:b0:25a:88b3:9af6 with SMTP id
 n14-20020a2ebd0e000000b0025a88b39af6mr6507869ljq.363.1659424012668; Tue, 02
 Aug 2022 00:06:52 -0700 (PDT)
MIME-Version: 1.0
References: <20220727071042.8796-4-feng.tang@intel.com> <YuYm3dWwpZwH58Hu@xsang-OptiPlex-9020>
 <YuY6Wc39DbL3YmGi@feng-skl> <Yudw5ge/lJ26Hksk@feng-skl> <0e545088-d140-4c84-bbb2-a3be669740b2@suse.cz>
 <YujKCxu2lJJFm73P@feng-skl>
In-Reply-To: <YujKCxu2lJJFm73P@feng-skl>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Aug 2022 09:06:41 +0200
Message-ID: <CACT4Y+Zwg8BP=6WJpQ5cCbJxLu4HcnCjx8e53aDEbTZ5uzpUyg@mail.gmail.com>
Subject: Re: [mm/slub] 3616799128: BUG_kmalloc-#(Not_tainted):kmalloc_Redzone_overwritten
To: Feng Tang <feng.tang@intel.com>
Cc: Vlastimil Babka <vbabka@suse.cz>, "Sang, Oliver" <oliver.sang@intel.com>, lkp <lkp@intel.com>, 
	LKML <linux-kernel@vger.kernel.org>, "linux-mm@kvack.org" <linux-mm@kvack.org>, 
	"lkp@lists.01.org" <lkp@lists.01.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, "Hansen, Dave" <dave.hansen@intel.com>, 
	Robin Murphy <robin.murphy@arm.com>, John Garry <john.garry@huawei.com>, 
	Kefeng Wang <wangkefeng.wang@huawei.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=gHKO1or5;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::236
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, 2 Aug 2022 at 08:55, Feng Tang <feng.tang@intel.com> wrote:
>
> On Mon, Aug 01, 2022 at 10:23:23PM +0800, Vlastimil Babka wrote:
> > On 8/1/22 08:21, Feng Tang wrote:
> [snip]
> > > Cc kansan  mail list.
> > >
> > > This is really related with KASAN debug, that in free path, some
> > > kmalloc redzone ([orig_size+1, object_size]) area is written by
> > > kasan to save free meta info.
> > >
> > > The callstack is:
> > >
> > >   kfree
> > >     slab_free
> > >       slab_free_freelist_hook
> > >           slab_free_hook
> > >             __kasan_slab_free
> > >               ____kasan_slab_free
> > >                 kasan_set_free_info
> > >                   kasan_set_track
> > >
> > > And this issue only happens with "kmalloc-16" slab. Kasan has 2
> > > tracks: alloc_track and free_track, for x86_64 test platform, most
> > > of the slabs will reserve space for alloc_track, and reuse the
> > > 'object' area for free_track.  The kasan free_track is 16 bytes
> > > large, that it will occupy the whole 'kmalloc-16's object area,
> > > so when kmalloc-redzone is enabled by this patch, the 'overwritten'
> > > error is triggered.
> > >
> > > But it won't hurt other kmalloc slabs, as kasan's free meta won't
> > > conflict with kmalloc-redzone which stay in the latter part of
> > > kmalloc area.
> > >
> > > So the solution I can think of is:
> > > * skip the kmalloc-redzone for kmalloc-16 only, or
> > > * skip kmalloc-redzone if kasan is enabled, or
> > > * let kasan reserve the free meta (16 bytes) outside of object
> > >   just like for alloc meta
> >
> > Maybe we could add some hack that if both kasan and SLAB_STORE_USER is
> > enabled, we bump the stored orig_size from <16 to 16? Similar to what
> > __ksize() does.
>
> How about the following patch:
>
> ---
> diff --git a/mm/slub.c b/mm/slub.c
> index added2653bb0..33bbac2afaef 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -830,6 +830,16 @@ static inline void set_orig_size(struct kmem_cache *s,
>         if (!slub_debug_orig_size(s))
>                 return;
>
> +#ifdef CONFIG_KASAN
> +       /*
> +        * When kasan is enabled, it could save its free meta data in the
> +        * start part of object area, so skip the kmalloc redzone check
> +        * for small kmalloc slabs to avoid the data conflict.
> +        */
> +       if (s->object_size <= 32)
> +               orig_size = s->object_size;
> +#endif
> +
>         p += get_info_end(s);
>         p += sizeof(struct track) * 2;
>
> I extend the size to 32 for potential's kasan meta data size increase.
> This is tested locally, if people are OK with it, I can ask for 0Day's
> help to verify this.

Where is set_orig_size() function defined? Don't see it upstream nor
in linux-next.
This looks fine but my only concern is that this should not increase
memory consumption when slub debug tracking is not enabled, which
should be the main operation mode when KASAN is enabled. But I can't
figure this out w/o context.


> Thanks,
> Feng
>
> >
> > > I don't have way to test kasan's SW/HW tag configuration, which
> > > is only enabled on arm64 now. And I don't know if there will
> > > also be some conflict.
> > >
> > > Thanks,
> > > Feng
> > >
> >
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YujKCxu2lJJFm73P%40feng-skl.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZwg8BP%3D6WJpQ5cCbJxLu4HcnCjx8e53aDEbTZ5uzpUyg%40mail.gmail.com.

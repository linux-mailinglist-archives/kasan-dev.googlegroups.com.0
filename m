Return-Path: <kasan-dev+bncBCQ2XPNX7EOBB6FJ2C2QMGQECFJWYSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F7A294B44B
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Aug 2024 02:44:42 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-2f1752568cfsf4092231fa.1
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Aug 2024 17:44:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723077882; cv=pass;
        d=google.com; s=arc-20160816;
        b=s7aj9u8DerGH/CnoKtEsa8SDsO2UdXvmm83W4cFD8+QQciroxUOt8GudYsIj8ZnYan
         285R5SyGrrx/CoODpMlilGIqTSePfYLceUcfrrcIiAscZPtY7WLwSpcT7iqQh0Yx3ZIo
         7P0H061FfhTTSqBBhUydKSngsNLxshL3EQtOweLUVfnBcZngu+f4vDBduWQzWWkyUuhs
         Wz/J4UMtE8A3FqWfMaNim9eSxLTL4x2NdI+GZqsDcf+0RNGEE9nlDUt0yKW0Vacvt0IV
         1Al45fsNHSgIiU0DNPa+SZSffSqcTsOiysewbZSnE+wKIhRv2uS+kb5642DfABVFUaWT
         sYVA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JoiHnKozanlYPUth8IaXGsOaPNImgjoYS0QJ0W1vU7w=;
        fh=CTgNDbT7XFGx2E6Kz68emw/0zc+FckhN3A6+Gi/P1lw=;
        b=KUezwqbYm+IH0Z2LTlsxbwvySTanx/HcCKbrlifS+cO70c18Rl9qin8cdtlz3MBUxm
         exVvrmndk7lJWI7XbwG706CKP5h6SPNfoaKptuROeMl+kSV4rQCCSz+DU/EYSkLHb4oV
         MKiaewT3L5Fmk/TxmYathRPSj3pzI6Lp1sxgSTXzi5vGdNqPyT/H1E2hUlFwjeKyOt5w
         9TJRkmsSqhv3C+wV2+QsfcQe8ksuf83/UC25ZSoO7c0hOq89ku8g8afzVoGU7rnJs3lR
         naCEMjg1z7UimqfOnvH93udeawnsPEcPMpSYm6wJzuzzPErJINxc11VhnvQxBeLuJWXs
         9U0w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ddey6JLf;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723077882; x=1723682682; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=JoiHnKozanlYPUth8IaXGsOaPNImgjoYS0QJ0W1vU7w=;
        b=PxbXYJ0MEZJVL8MNRERDXB9zqhwQDyP2vNtu2ypqvryEuGKffGtrxUeHLUbs/PbiQN
         FjxSuolV9YwxHYkPe5KG2AtzcMsUINFMbx/xyqRBPZhxNYatQEOUXEx5s8R9TfkbbTYY
         5zAndk5Qv00vUK+ns6rqw9qgQdXsKk2nZdgtNTfYXwiQkHnTx0hdfNHWkA7tVGKC7O/w
         YejgD26XyLgXqQZXLaOOeglMmHkTd+zyCXxPoRFcDL9zz7Hn36oqPJhbEmCJhJBJ26dL
         fo67ueg3rFcy/etrSO9sT9HLWj3vulez9Yny3/AsoNaLJlhhdoyRamyiantVJWvO9z7I
         jgZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723077882; x=1723682682;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=JoiHnKozanlYPUth8IaXGsOaPNImgjoYS0QJ0W1vU7w=;
        b=mFT1YKj+2AqbN1yqxv3YLG/KPnFZ/wfe/cFZaTfnA9fEsAUcjZRpaEHDcJXvLusgZF
         lTntFbfcYFivOvYLam+ca9yPrUmtbml+h6aMT6FTMkz/j5qlpkc6HKVbjqOQiC2nccy1
         KhswrIhBmGbtFlVmeCf8DeXQxw32NohjRrM/7RDUAfSJWzfZ0jCmDrg2hNnNR+TqBdPm
         YYyAZ2qwB+HwlU+NsHP81kdgnzOf66qpcF6V7VPOcWSZwIUQcJ6Lkoudv8ZjQ352ze9E
         u8AjQprEkfc3Pmx19j6ALHqf2q0A6G2mJt5FIaZ9Tt86MOUQdOngWTkjyAzYdLJMvuti
         6lRw==
X-Forwarded-Encrypted: i=2; AJvYcCVTVQbwnrPtxvoOiXGg1MN+PdMkFKDoRIhoI2m/uA2KYCPs1gyZWotZoyO+reTOhwl9ZALU0Q==@lfdr.de
X-Gm-Message-State: AOJu0YzXMKxRpq5cUObuR4V7rjXROOY/9LWN+qyAySd29oi5OFBeDqtk
	wx374fshwKZTC5BZjtD1alcjE4y9O3cvxHtEaZssT70NuxBXD4am
X-Google-Smtp-Source: AGHT+IHAARyhP+xPImAqFiez2P8luzi393TTs8yApiKh0Xee/I2jAoqVomD7nyPsxRb2l813r2x6uA==
X-Received: by 2002:a05:651c:b09:b0:2ef:290e:4a2b with SMTP id 38308e7fff4ca-2f19de66665mr1506401fa.38.1723077881187;
        Wed, 07 Aug 2024 17:44:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:2a46:0:b0:2ef:1eb3:4737 with SMTP id 38308e7fff4ca-2f19bb19e68ls1495821fa.0.-pod-prod-03-eu;
 Wed, 07 Aug 2024 17:44:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUvm7BpOITIhV/sUvnlmVGt9pcv0RCs9gv8jHrDPrvDNmGUArWv8/dqlFPS5T5P64Hqbi0W3/TxzBE=@googlegroups.com
X-Received: by 2002:a05:651c:1546:b0:2ef:22ef:a24e with SMTP id 38308e7fff4ca-2f19de1f9ddmr1655571fa.10.1723077879094;
        Wed, 07 Aug 2024 17:44:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723077879; cv=none;
        d=google.com; s=arc-20160816;
        b=H0ymW1OkPgnjWnfYywBRBidFDVTLTk27BYjpls4/79q7rX0je7jAtC3FvzbPaFl0M3
         XSFegUPpAgOkKJS/DQfUwvjqUe+EtaaiIe5Fh+wGuB3j/NK1jVlglkTjPex14A30oxCO
         pKenoCJKNJTxDiQSBkIBITA3JIGozFs3aDrEbmJNYPTXCurPaFBSjdxroRVxc6LGCJZR
         JOCzZ6jXuk756pNB67MaeYJ6g/9wc4mG/ruR6U6PT1UoRzAQLFA4xoPTxUE3dpgo4QLj
         BMLwOZ/O9tQLXBzsHSEb+APCSW9o35hyGEjOR7Rp/iQkRHyI0Cncmlkw1fKd+bg0rO7G
         kcLw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=IBshlEm/hRezkXwc4E0KD/35MsKepvejjcK36JSLpHw=;
        fh=D7xUlVxJSkuPP4eoSR+ahFG/8uJ226xWhGt56DJSOVI=;
        b=t/8491g6LkEOdMSv3n283ClU7wpwYu8+DakEHDTSwW9lB7gUihuKBYlHNwagH2G2jH
         tzTG5+OPwne6p+Oe8Mpfhm794b4cA8HzaxJzwdJJ/uU7UzmClf7hbuhs5oOR2jB8l+sF
         OX3pedlALlRtEW8O+9BAMcd6hA7rgO6IigXTSzsrax2OwMxA0l2+fo8AdMy0hRF08ypG
         DP3FZp3IX41KZrH0O08xFsFwin+liuhcEQmsBAMurO6/22XhLDp7egIa37dyoEoi5km/
         InubWM/o/IIumBQYMbLX0vRmbP18WVhxZj17gv04mJO7NhYqQ9eIXN3hvupSw0gJ3hnk
         3QtQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ddey6JLf;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x52e.google.com (mail-ed1-x52e.google.com. [2a00:1450:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2f15e25d3fasi2573751fa.3.2024.08.07.17.44.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 Aug 2024 17:44:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52e as permitted sender) client-ip=2a00:1450:4864:20::52e;
Received: by mail-ed1-x52e.google.com with SMTP id 4fb4d7f45d1cf-5a18a5dbb23so4294a12.1
        for <kasan-dev@googlegroups.com>; Wed, 07 Aug 2024 17:44:39 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUWYF1YVrcq1cW7NWdx9OYJxlDrE+O+cjrK6jHnWviVh0NGi+XcyXPR2rQiplwmJ1bZ3HuCzNSXw2g=@googlegroups.com
X-Received: by 2002:a05:6402:3496:b0:58b:15e4:d786 with SMTP id
 4fb4d7f45d1cf-5bbb1797fd1mr44545a12.5.1723077877633; Wed, 07 Aug 2024
 17:44:37 -0700 (PDT)
MIME-Version: 1.0
References: <20240802-kasan-tsbrcu-v6-0-60d86ea78416@google.com>
 <20240802-kasan-tsbrcu-v6-2-60d86ea78416@google.com> <c41afd73-97b4-4683-96a1-0da4a4dfeb2b@suse.cz>
In-Reply-To: <c41afd73-97b4-4683-96a1-0da4a4dfeb2b@suse.cz>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 8 Aug 2024 02:44:00 +0200
Message-ID: <CAG48ez0VHMFNAFGKV5yPCrJw16-_avDHJB+YTJaxaXuC6+WSYw@mail.gmail.com>
Subject: Re: [PATCH v6 2/2] slub: Introduce CONFIG_SLUB_RCU_DEBUG
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, David Sterba <dsterba@suse.cz>, Marco Elver <elver@google.com>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	syzbot+263726e59eab6b442723@syzkaller.appspotmail.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=ddey6JLf;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52e as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Wed, Aug 7, 2024 at 11:26=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
> On 8/2/24 22:31, Jann Horn wrote:
> > Currently, KASAN is unable to catch use-after-free in SLAB_TYPESAFE_BY_=
RCU
> > slabs because use-after-free is allowed within the RCU grace period by
> > design.
> >
> > Add a SLUB debugging feature which RCU-delays every individual
> > kmem_cache_free() before either actually freeing the object or handing =
it
> > off to KASAN, and change KASAN to poison freed objects as normal when t=
his
> > option is enabled.
> >
> > For now I've configured Kconfig.debug to default-enable this feature in=
 the
> > KASAN GENERIC and SW_TAGS modes; I'm not enabling it by default in HW_T=
AGS
> > mode because I'm not sure if it might have unwanted performance degrada=
tion
> > effects there.
> >
> > Note that this is mostly useful with KASAN in the quarantine-based GENE=
RIC
> > mode; SLAB_TYPESAFE_BY_RCU slabs are basically always also slabs with a
> > ->ctor, and KASAN's assign_tag() currently has to assign fixed tags for
> > those, reducing the effectiveness of SW_TAGS/HW_TAGS mode.
> > (A possible future extension of this work would be to also let SLUB cal=
l
> > the ->ctor() on every allocation instead of only when the slab page is
> > allocated; then tag-based modes would be able to assign new tags on eve=
ry
> > reallocation.)
> >
> > Tested-by: syzbot+263726e59eab6b442723@syzkaller.appspotmail.com
> > Signed-off-by: Jann Horn <jannh@google.com>
>
> Actually, wait a second...
>
> > +#ifdef CONFIG_SLUB_RCU_DEBUG
> > +static void slab_free_after_rcu_debug(struct rcu_head *rcu_head)
> > +{
> > +     struct rcu_delayed_free *delayed_free =3D
> > +                     container_of(rcu_head, struct rcu_delayed_free, h=
ead);
> > +     void *object =3D delayed_free->object;
> > +     struct slab *slab =3D virt_to_slab(object);
> > +     struct kmem_cache *s;
> > +
> > +     if (WARN_ON(is_kfence_address(object)))
> > +             return;
> > +
> > +     /* find the object and the cache again */
> > +     if (WARN_ON(!slab))
> > +             return;
> > +     s =3D slab->slab_cache;
> > +     if (WARN_ON(!(s->flags & SLAB_TYPESAFE_BY_RCU)))
> > +             return;
> > +
> > +     /* resume freeing */
> > +     if (!slab_free_hook(s, object, slab_want_init_on_free(s), true))
> > +             return;
> > +     do_slab_free(s, slab, object, object, 1, _THIS_IP_);
> > +     kfree(delayed_free);
>
> This will leak memory of delayed_free when slab_free_hook() returns false
> (such as because of KASAN quarantine), the kfree() needs to happen always=
.
> Even in the WARN_ON cases but that's somewhat less critical.

... oh. Indeed. I guess really I can just move the kfree(delayed_free)
up before the first bailout, we're not accessing anything in it after
loading the ->object member...

> Thanks to David Sterba for making me look again, as he's been asking me
> about recent OOMs in -next with heavy kmalloc-32 cache usage (delayed_fre=
e
> is 24 bytes) and CONFIG_SLUB_RCU_DEBUG was so far almost certainly confir=
med.

Nice catch...

I guess I'll get to send a v7 of the series.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG48ez0VHMFNAFGKV5yPCrJw16-_avDHJB%2BYTJaxaXuC6%2BWSYw%40mail.gm=
ail.com.

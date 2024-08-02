Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBGEDWO2QMGQEZBV73XA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id A965F945D33
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Aug 2024 13:23:05 +0200 (CEST)
Received: by mail-ed1-x540.google.com with SMTP id 4fb4d7f45d1cf-5a2ceb035f9sf4237627a12.0
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Aug 2024 04:23:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722597785; cv=pass;
        d=google.com; s=arc-20160816;
        b=IBaxfcJLCw0uX/HgIwK8cAehBr63YfpEoU7+KxIFQ68KH8rA6CfpSsuCCOklExLqyo
         it2cSrKprO+9cP8i0fMgSAjuJWUG2PY9cfaQFIGqxgjc26SrCYDJG2dS0m/Fb/dofLL9
         M0LVL1tyjtaZzhdC+WbyCEGKL93wPRBXz3DA++UpG1ODE2/GM7EYaF4dI63tPGr3u81B
         sOLIM7Q4TCshj5Z5+BAZ3jfOJBC95kJHq2yWA4HBRQopZxJx0Eht6lXI6tn94AFF717w
         AkfNxWmi0Ckg8xmJIe/EGFDGnweWhIXuxfTuPYlxpc767gm11XHstOetRUQLdERuys5l
         BlLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=cwVLfqvvmeBwoOWWwcUvpjgge8/wWlTX1ZGxncYuw/c=;
        fh=S3qafdPsf5pv5q7mhF4ccW/HHZw9+Tl6iv6/YlTZccg=;
        b=K0Pr3WJPhmATqQ8CZhYZGpNbhp6YK+aeoMsWZRLot4/Qa2tX1EN4snTmNalyB1GLp1
         i+gGGjmoZkqyLiUG2EjYsTGsS1iiuwzsYfVRtiCyfTn8ou79XI6nlgyYXqEjdPuQJyZE
         YJeNKGADWGDyVcaZDUDMjPMr+V7CW2nmymoiAnyECBn3RAdloQMrVJvImhJ3eaceHqDS
         6X3URCOdrEo0Y/OsjqpZtiScrs/E0DoqMbJLXCRxIwIYMXwNpqSqQNPhvF9S9iupcaJK
         0yvB7zCmbce7tuWya4M/mtFUp6OW7waD/YyCjuphXhM7r53CSQoOTCurRh5IuBcBVC/p
         tbjw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=gWRliGZK;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::536 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722597785; x=1723202585; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=cwVLfqvvmeBwoOWWwcUvpjgge8/wWlTX1ZGxncYuw/c=;
        b=CSb5AQv8w9YpFh/NertQ+QUF4uHd1CcgtfyhFmEx1ReDZifoXVmG+pNDjWlWE6r8ET
         1+0rGNlIpfF/RBKt2IoSLvSRzc6CrZwG+wJvss0W7DMoi8HZuCCbnfRSxNhl7MXHN4BA
         kyj0f+iWQ9gHbiEtfHL30u24RphoT3n+4Z9ues+e3B0/eqWiTyAnlvDyiza/SJnm7rHk
         9YMi3PezM9b1UzzJvOI6v0AvP0QYQij2686UVf1+ZAkGx76m2qrZpVp6R3t72J3Cc13n
         ntU/i5u27dt1i8AofMDraS7ngaTE8+7NdL91RKomS6STjT+8Y1FU0SfPpyyRBtUYO+rH
         EoEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722597785; x=1723202585;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=cwVLfqvvmeBwoOWWwcUvpjgge8/wWlTX1ZGxncYuw/c=;
        b=ewjSg9vFJosQU80bQiy6irnzFFMeNcR7IHIKnZYh/vhVV6K9vENARQ1ImKxGGkKbbc
         0AvmAf+7xnyCjIhLgdV5RYx3kTHkBJXmIWZPFojvIVcNmxOSFrU5IXC7mUYu/tzTI/bD
         HAbPuPbZsjtSQIGzQW4tcqlONRJ4+WpzmN5V0R3Ac2XTqpCgKSwiXQqyRKWPB7U8qbmC
         7RC1j2wUsdVI/wz35WvqRPdzAH1hVxtY+PCtWgdcPIKFjXdjl1knYn5xRwcn4zppdWPb
         drhjU8Rz4FPKV4kfhbEn5eDKiDc0Sie6iOrBnWInyhDWeAqeS9C1RnszyxYcPP801XWh
         oeAQ==
X-Forwarded-Encrypted: i=2; AJvYcCU1V7UleBcTWOY187FyqCstAm0zvkyY5vnsO43a8zB/FaomtenJ5+cu704n7D73aMAFKsIseTQya7DTQuP2mSYRuO45c5d4WA==
X-Gm-Message-State: AOJu0YyJGxyaRUhiaEuz6mUvdxlTI5X9wTqEdDh1Ugd/MSJEYJV776lh
	fAuH+s427Sb9ogoj7M+UWrtX0E0y4piS8P/RRMHE1FCO1H0dMaiU
X-Google-Smtp-Source: AGHT+IHb/kVuQspbk3hwfSHog3SvacoDcnl3Ddi1QA9ZWkmfxmywB/vteFIz8ysYlyY0pvTTBcc/4g==
X-Received: by 2002:a05:6402:5173:b0:58c:b2b8:31b2 with SMTP id 4fb4d7f45d1cf-5b80cdac888mr2543634a12.17.1722597784714;
        Fri, 02 Aug 2024 04:23:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:27c8:b0:5b1:4ae:cd0f with SMTP id
 4fb4d7f45d1cf-5b7f05de1d5ls132123a12.2.-pod-prod-00-eu; Fri, 02 Aug 2024
 04:23:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVTcKuijyM99JDp8B+hFzIx+PnqfQJeXC/CxoWBEyhsFpPmY9PF2ljFRKnDYz8FHsY/EDroUNk42oeET87RPEj8vGG0H4Sl0hSAXw==
X-Received: by 2002:a17:907:d8a:b0:a77:c051:36a9 with SMTP id a640c23a62f3a-a7dc5fb4baamr282469366b.9.1722597782649;
        Fri, 02 Aug 2024 04:23:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722597782; cv=none;
        d=google.com; s=arc-20160816;
        b=UHDVz273vCBo4YPlzf6fYWBFrXHWmUYgkYi5p7IPHqiSSeMKIQJnVuJRXw7LmQu2sE
         RaJjbC5Cli2JffZSZaCjRYEFMd8yDp01DbSXFq67RghAcZr2yEfDFxwT062dPVON+OrG
         KX74d4nqxsqhTvlmXV/W+MI9RzIkhI9gUpSMFq7aCIcovplJpeo9YKoWjPNOK7phzYkF
         /OBDhHoPEUULtFo5OvcNliTO06JGT+Yq41CmLA7Hs7b5kHbKRJ+p0/WykcQZ5ApeLB8a
         tZaWMXQKaMF51kfOPBsLOlKvkoTNTOD9P6qnypGEMphJA9LSXdfJq+0lu8QICyO9icYh
         Fx+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=TXuC7eL0okWOe+3ruv5rtgdzN2mMwl0ZfQ5u9zC8B54=;
        fh=Mkzm5KpeLcne4rfbYzv646lXOmirXEjN2R0hSI3hvnY=;
        b=gdjRaSi5kaVPx5MkdxhypJicrqtVomFC57EhLZgIxWrU0nLEdOxRkr1j8oTYj23yxS
         7stOHDnvrWEhnOsVEXs1wF/JheE4iuNo2GXXZSSZVThuHt38fHrkwzVNM97hjRi9WO19
         UKiZMkn0NOFQ9A0/ry05T5shK8lMCACK/fG50Vupc4XpNgDpJSm/kGlissLnKzfAmFL7
         PPVtWr723++GmZPZgiV6VTfH/LDwVhE9/bNgsTnIB4zRPfMMgakJVxZNt2hhN9KYXDPh
         xIn+AT/5krK/zfYN7rhV3c2cjgGhNMAO/QfKwN7WcrO+6Mw8DhJ1J6+9wdHKuPnejlYq
         55BQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=gWRliGZK;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::536 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x536.google.com (mail-ed1-x536.google.com. [2a00:1450:4864:20::536])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-a7dc9d1689asi3913066b.1.2024.08.02.04.23.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Aug 2024 04:23:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::536 as permitted sender) client-ip=2a00:1450:4864:20::536;
Received: by mail-ed1-x536.google.com with SMTP id 4fb4d7f45d1cf-5a869e3e9dfso50942a12.0
        for <kasan-dev@googlegroups.com>; Fri, 02 Aug 2024 04:23:02 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV9LUSQEXq3TGejhNQyCqwYttA6mFX+r7fYbAGccvzROLrSmEp8q0dboW37TTjWQjvZeY2ir9gVuAfOcnEQp05THTq/YR6qHjZlYA==
X-Received: by 2002:a05:6402:40cf:b0:5ac:4ce3:8f6a with SMTP id
 4fb4d7f45d1cf-5b86bf8e337mr112549a12.6.1722597781429; Fri, 02 Aug 2024
 04:23:01 -0700 (PDT)
MIME-Version: 1.0
References: <20240730-kasan-tsbrcu-v5-0-48d3cbdfccc5@google.com>
 <20240730-kasan-tsbrcu-v5-2-48d3cbdfccc5@google.com> <CA+fCnZeq8JGSkFwGitwSc3DbeuoXnoyvC7RgWh6XSG1CoWH=Zg@mail.gmail.com>
 <CAG48ez1guHcQaZtGoap7MG1sac5F3PmMA7XKUH03pEaibvaFJw@mail.gmail.com>
In-Reply-To: <CAG48ez1guHcQaZtGoap7MG1sac5F3PmMA7XKUH03pEaibvaFJw@mail.gmail.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 2 Aug 2024 13:22:23 +0200
Message-ID: <CAG48ez2bqYMPS2D7gFZ-9V3p3-NJUYmYNA113QbMg0JRG+pNEQ@mail.gmail.com>
Subject: Re: [PATCH v5 2/2] slub: Introduce CONFIG_SLUB_RCU_DEBUG
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>, 
	Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	Marco Elver <elver@google.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=gWRliGZK;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::536 as
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

On Fri, Aug 2, 2024 at 11:09=E2=80=AFAM Jann Horn <jannh@google.com> wrote:
> I guess I could also change the API to pass something different - like
> a flag meaning "the object is guaranteed to no longer be in use".
> There is already code in slab_free_hook() that computes this
> expression, so we could easily pass that to KASAN and then avoid doing
> the same logic in KASAN again... I think that would be the most
> elegant approach?

Regarding this, I think I'll add something like this on top of this patch i=
n v6:

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index b63f5351c5f3..50bad011352e 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -201,16 +201,17 @@ bool __kasan_slab_free(struct kmem_cache *s,
void *object, bool init,
 /**
  * kasan_slab_free - Possibly handle slab object freeing.
  * @object: Object to free.
+ * @still_accessible: Whether the object contents are still accessible.
  *
  * This hook is called from the slab allocator to give KASAN a chance to t=
ake
  * ownership of the object and handle its freeing.
  * kasan_slab_pre_free() must have already been called on the same object.
  *
  * @Return true if KASAN took ownership of the object; false otherwise.
  */
 static __always_inline bool kasan_slab_free(struct kmem_cache *s,
                                                void *object, bool init,
-                                               bool after_rcu_delay)
+                                               bool still_accessible)
 {
        if (kasan_enabled())
                return __kasan_slab_free(s, object, init, after_rcu_delay);
@@ -410,7 +411,7 @@ static inline bool kasan_slab_pre_free(struct
kmem_cache *s, void *object)
 }

 static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
-                                  bool init, bool after_rcu_delay)
+                                  bool init, bool still_accessible)
 {
        return false;
 }
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 71a20818b122..ed4873e18c75 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -230,14 +230,14 @@ static bool check_slab_allocation(struct
kmem_cache *cache, void *object,
 }

 static inline void poison_slab_object(struct kmem_cache *cache, void *obje=
ct,
-                                     bool init, bool after_rcu_delay)
+                                     bool init, bool still_accessible)
 {
        void *tagged_object =3D object;

        object =3D kasan_reset_tag(object);

        /* RCU slabs could be legally used after free within the RCU period=
. */
-       if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU) && !after_rcu_del=
ay)
+       if (unlikely(still_accessible))
                return;

        kasan_poison(object, round_up(cache->object_size, KASAN_GRANULE_SIZ=
E),
@@ -256,12 +256,12 @@ bool __kasan_slab_pre_free(struct kmem_cache
*cache, void *object,
 }

 bool __kasan_slab_free(struct kmem_cache *cache, void *object, bool init,
-                      bool after_rcu_delay)
+                      bool still_accessible)
 {
        if (!kasan_arch_is_ready() || is_kfence_address(object))
                return false;

-       poison_slab_object(cache, object, init, after_rcu_delay);
+       poison_slab_object(cache, object, init, still_accessible);

        /*
         * If the object is put into quarantine, do not let slab put the ob=
ject
diff --git a/mm/slub.c b/mm/slub.c
index 49571d5ded75..a89f2006d46e 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -2221,31 +2221,34 @@ static __always_inline
 bool slab_free_hook(struct kmem_cache *s, void *x, bool init,
                    bool after_rcu_delay)
 {
+       /* Are the object contents still accessible? */
+       bool still_accessible =3D (s->flags & SLAB_TYPESAFE_BY_RCU) &&
!after_rcu_delay;
+
        kmemleak_free_recursive(x, s->flags);
        kmsan_slab_free(s, x);

        debug_check_no_locks_freed(x, s->object_size);

        if (!(s->flags & SLAB_DEBUG_OBJECTS))
                debug_check_no_obj_freed(x, s->object_size);

        /* Use KCSAN to help debug racy use-after-free. */
-       if (!(s->flags & SLAB_TYPESAFE_BY_RCU) || after_rcu_delay)
+       if (!still_accessible)
                __kcsan_check_access(x, s->object_size,
                                     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSE=
RT);

        if (kfence_free(x))
                return false;

        /*
         * Give KASAN a chance to notice an invalid free operation before w=
e
         * modify the object.
         */
        if (kasan_slab_pre_free(s, x))
                return false;

 #ifdef CONFIG_SLUB_RCU_DEBUG
-       if ((s->flags & SLAB_TYPESAFE_BY_RCU) && !after_rcu_delay) {
+       if (still_accessible) {
                struct rcu_delayed_free *delayed_free;

                delayed_free =3D kmalloc(sizeof(*delayed_free), GFP_NOWAIT)=
;
@@ -2289,7 +2292,7 @@ bool slab_free_hook(struct kmem_cache *s, void
*x, bool init,
                       s->size - inuse - rsize);
        }
        /* KASAN might put x into memory quarantine, delaying its reuse. */
-       return !kasan_slab_free(s, x, init, after_rcu_delay);
+       return !kasan_slab_free(s, x, init, still_accessible);
 }

 static __fastpath_inline

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG48ez2bqYMPS2D7gFZ-9V3p3-NJUYmYNA113QbMg0JRG%2BpNEQ%40mail.gmai=
l.com.

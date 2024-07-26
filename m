Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBB6UR22QMGQEE3QRFUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id C86DE93D49B
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Jul 2024 15:52:08 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-2ef17c96309sf13925241fa.2
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Jul 2024 06:52:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722001928; cv=pass;
        d=google.com; s=arc-20160816;
        b=Rp1h5+o32nfsfk5BtDnUBz0mTKuv4N6D9Z4nmjWEzgTG6a3PRCK+8WPnKrkoPEnWGl
         5l5wP7TNUlSlSEsUd+mTPj/vIKKShJxFaDw858CMEgp3R1079PToMCBAbtCQa6A9y5Il
         lE3G91h/aq/MEOTOMR4erLjaLcogs6rqtXyrTNIEc4jG0xBXBuw7d87blX3RIedsfcVv
         j/J1XkbGVg/THr2COUSafbLJL3hQNrpyv7Vg6mIAVRcAIWk2jjahYF8xwn/nWL10cvLL
         XIj4WMHs3hmziGsYDSEYLAQjjr0sGBos7CZykGElmWV0gSougPiS7z6e0A5UQn7QYph7
         Q3HA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2kuKt3F3brIzV7qTHzZ6NLVPBvIBYrGOvoECcZgX44I=;
        fh=OsIDWL4nEcY8og2DnKaJmS0GyT+3NtotOnBU25CgGGI=;
        b=todpkTYkmBREuRPy3GGFCnuMnlYeVCw0x6leQMkn2YgSZBQwn5uUW0sQGXbLQbWhIG
         wM7UjaTPC6ecawP07N8KCeul7pPnnGzCrYsBHosKPA2RELczVxStsSMBy+egDDTIbENJ
         2UuaX599CKr435SSfiCT8rVSaRQXCrThhvLVEGb4cagYjE1Arh1XJmZ2u03ONZ7JHydx
         Crri+6QhZLsqHYYS+0J+9aJlzvZvbVGt9d6VxziMshsiAIWm3zDajz5nNMAZmCogcOAJ
         X1iGldOOkZfIhkGgdfY/m/oKCGxiyhDoE4ek1aitO7IkVczRk3RSh8+d7jcGKoAz0rSQ
         bwxw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=SGQnZQ7T;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::533 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722001928; x=1722606728; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=2kuKt3F3brIzV7qTHzZ6NLVPBvIBYrGOvoECcZgX44I=;
        b=kjKBNOrCg/RhTBgEKIuevQPQJz7/2OQWnSs5qdeyhL5Z6unZDXihQ4Y2VKE5buPiFc
         Ze8brfjYGLLR56/jjMu91x9vpLxUjn9npDFcTCHlWs/p/bgnoe4bUp2v82MVEjB6fl1w
         dFI+AzZyZjAhamZDZgsvbGbD0mbr+sltSH416x90NbuECzyDpMyjVudwON5sRV7sl3N/
         pIBn3izNlV7PmMDg8AO1GZXOhBPRpKZvN/YiNnXV78TdlcN+LylyugUVyefdXPCQ2LrN
         YqsQ4SOxGvm67BS18mL2lDXlCVcPHji5rsObl2f7UqA36oDrhkmsYOdjw/mXshArBWyg
         zieA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722001928; x=1722606728;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=2kuKt3F3brIzV7qTHzZ6NLVPBvIBYrGOvoECcZgX44I=;
        b=l5bH3sAwLwLx6aXwRdutoM8ldrCyCreMd1ZUpD6Oj/i1bBHSgD8CasLs8NjOwq3g+4
         MVKyrDGIZ0PB1ve2XUD6tLQjPvPr0Url+v7J/yl+OVNt0BtzZePR2oh8JGgnQnaqgesl
         HkQELU5CAOuLZdm8YC6lgM+XvkgFuZ4X1PGW0kodQh1iYqRZ420+80ulRxSL/Q+q4A0U
         QjizpkzBIoc5oDcq1JLR+L8QHB0hQ6vbH5yrN43V3hQmldcvWR7sgAB3QZyf3DclRFYZ
         0ArH4Ld6KNs3oFv+fcERtscyQ9McE1HuCOlilXD+AO8AnIHrbgE3X1vzjvLS3nmQUDy8
         4P5w==
X-Forwarded-Encrypted: i=2; AJvYcCWje7Yze7neavHKQDOzsBzCm7oHh8hPxLPuPfbVhiMKmELacl8knMo6H5DR79vyYf+IlFMYRIMJBGF3u0dGft/lYWlJMcE6Fw==
X-Gm-Message-State: AOJu0Yz4QvcidyFYvdAWpGweyrSrVz93XkMPvavM7kOgR3k9wqLnNlb+
	wyBsWIw78xW6Qasi4RgI8XR/OxDqLAPWUewDq9bhGu0UHYv2Plij
X-Google-Smtp-Source: AGHT+IE4+y4/tToU2apc9ELAOYpFMhmHLjNrX+k1XjgXBxvr1Hvy0QllDCrfJOVlv7N05ZFGrZD8QA==
X-Received: by 2002:a2e:9ed9:0:b0:2ee:5ed4:792f with SMTP id 38308e7fff4ca-2f039c8f224mr45631011fa.2.1722001927251;
        Fri, 26 Jul 2024 06:52:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:2110:b0:2ef:1eb3:473b with SMTP id
 38308e7fff4ca-2f03a2b4be5ls11205451fa.0.-pod-prod-02-eu; Fri, 26 Jul 2024
 06:52:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVob2X/k91KGqhenn2+0gIPyUTqghX7FzVy/TU/egg3PRB1fceGUt8SjScZl5cEMjCUImNh8cDACiVH9xch/5IqaRPTSNJ7HSmKNA==
X-Received: by 2002:a05:6512:124f:b0:52d:259d:bd91 with SMTP id 2adb3069b0e04-52fd3f11c7dmr4304573e87.18.1722001925125;
        Fri, 26 Jul 2024 06:52:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722001925; cv=none;
        d=google.com; s=arc-20160816;
        b=NyE4aUeRin04YperBWCX8QvogyVf0A7iZMRPwEAxkLVxEDnDSGIsq3e1q8+IgikqDm
         Z2A+0mes0U6VYUlsesZNSTQht8YZT6piJusleB1bo2R546mIT13uLp1KHel1pz0hasSO
         qo4uyXsYNTTvezW+xIlvdtpqWEl3r1zn9AxOithtx927slT873nSwsicHlX7rc93m/Ae
         uPyqN0uRZtlQLEEpeSMcXaMKjWJS+uMat6fDGDhW881Vbv27TStYaNUBBeNS8NVFgARD
         DvmzcTgeg+QPozw59N+vaCqUCsK7BUk2e47HMAhz+VwEx5JORDt61UvYyaAdPs1Qa2Hk
         oFJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=bzST+WgYB+YniWsc5gywqmeeedMARG6ljFEX5tmeU7g=;
        fh=G2ofFJjAQHArlqwz+y2iKvluUXNoge1jYrHKmd6CxXc=;
        b=e1ldP5BUkTgR0t6mICHyo2Kol+eQhVTHcLEqGgxZdQwOSR/72rUie1e8eIN5go8Fdq
         FwX8Kp+7M+1hp8eCMI5MGwwwPO/728eaMqSnBVff15On9k2KInFRRQKgT1C5cpAR2iuM
         Jp4wJ60Xqki+7FWoH5wx8oOUEHUeNgVXasA1a0YwopkzJ1oono733j8gkR/Q6Z3EWQf4
         8+wtHH31lAtYzJPKzoLkJyINyfY7PmMrRWEKl5tpqxDhYT3j8Z5Shu4T094Lsg+iPs4A
         tKgkf14cw8dzrpGtcfL3oT4mPrGwG9AE3ZKnVrUePkIVk2F8el2ebs48G+yjDVPD9Dga
         /LGg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=SGQnZQ7T;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::533 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x533.google.com (mail-ed1-x533.google.com. [2a00:1450:4864:20::533])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-52fd5bde8ebsi79992e87.11.2024.07.26.06.52.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Jul 2024 06:52:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::533 as permitted sender) client-ip=2a00:1450:4864:20::533;
Received: by mail-ed1-x533.google.com with SMTP id 4fb4d7f45d1cf-5a1b073d7cdso15470a12.0
        for <kasan-dev@googlegroups.com>; Fri, 26 Jul 2024 06:52:05 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWXt+aoVtxyRO3xH9G/4LueBJOxp2SDZaMXGObZkSNQ+uZ5vY1SXQBP64/zkCqCXk/Co0XHmK9k52/1ngvizDXgYhIhdA2hy8Bu8w==
X-Received: by 2002:a05:6402:354f:b0:58b:15e4:d786 with SMTP id
 4fb4d7f45d1cf-5af44348136mr79918a12.5.1722001923695; Fri, 26 Jul 2024
 06:52:03 -0700 (PDT)
MIME-Version: 1.0
References: <20240725-kasan-tsbrcu-v3-0-51c92f8f1101@google.com>
 <20240725-kasan-tsbrcu-v3-1-51c92f8f1101@google.com> <CA+fCnZe-x+JOUN1P-H-i0_3ys+XgpZBKU_zi06XBRfmN+OzO+w@mail.gmail.com>
In-Reply-To: <CA+fCnZe-x+JOUN1P-H-i0_3ys+XgpZBKU_zi06XBRfmN+OzO+w@mail.gmail.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 26 Jul 2024 15:51:25 +0200
Message-ID: <CAG48ez0hAN-bJtQtbTiNa15qkHQ+67hy95Aybgw24LyNWbuU0g@mail.gmail.com>
Subject: Re: [PATCH v3 1/2] kasan: catch invalid free before SLUB
 reinitializes the object
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
 header.i=@google.com header.s=20230601 header.b=SGQnZQ7T;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::533 as
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

On Fri, Jul 26, 2024 at 2:43=E2=80=AFAM Andrey Konovalov <andreyknvl@gmail.=
com> wrote:
> On Thu, Jul 25, 2024 at 5:32=E2=80=AFPM Jann Horn <jannh@google.com> wrot=
e:
> >
> > Currently, when KASAN is combined with init-on-free behavior, the
> > initialization happens before KASAN's "invalid free" checks.
> >
> > More importantly, a subsequent commit will want to use the object metad=
ata
> > region to store an rcu_head, and we should let KASAN check that the obj=
ect
> > pointer is valid before that. (Otherwise that change will make the exis=
ting
> > testcase kmem_cache_invalid_free fail.)
>
> This is not the case since v3, right?

Oh, you're right, this text is now wrong.

> Do we still need this patch?

I just tried removing this patch from the series; without it, the
kmem_cache_invalid_free kunit test fails because the kmem_cache_free()
no longer synchronously notices that the pointer is misaligned. I
guess I could change the testcase like this to make the tests pass
without this patch, but I'd like to hear from you or another KASAN
person whether you think that's a reasonable change:

diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index cba782a4b072..f44b0dcb0e84 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -981,14 +981,21 @@ static void kmem_cache_invalid_free(struct kunit *tes=
t)
        if (!p) {
                kunit_err(test, "Allocation failed: %s\n", __func__);
                kmem_cache_destroy(cache);
                return;
        }

-       /* Trigger invalid free, the object doesn't get freed. */
-       KUNIT_EXPECT_KASAN_FAIL(test, kmem_cache_free(cache, p + 1));
+       /*
+        * Trigger invalid free, the object doesn't get freed.
+        * Note that the invalid free detection may happen asynchronously
+        * under CONFIG_SLUB_RCU_DEBUG.
+        */
+       KUNIT_EXPECT_KASAN_FAIL(test, ({
+               kmem_cache_free(cache, p + 1);
+               rcu_barrier();
+       }));

Being able to get rid of this patch would be a nice simplification, so
if you think asynchronous invalid-free detection for TYPESAFE_BY_RCU
slabs is fine, I'll happily throw it out.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG48ez0hAN-bJtQtbTiNa15qkHQ%2B67hy95Aybgw24LyNWbuU0g%40mail.gmai=
l.com.

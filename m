Return-Path: <kasan-dev+bncBDW2JDUY5AORBYPM32GAMGQEDWJC2SI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 3450D4570C4
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Nov 2021 15:36:19 +0100 (CET)
Received: by mail-il1-x139.google.com with SMTP id h14-20020a056e021d8e00b002691dcecdbasf6464033ila.23
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Nov 2021 06:36:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637332578; cv=pass;
        d=google.com; s=arc-20160816;
        b=qVE7mKEqRyVN7PfR7MViY27ec06eBDonNiOWeOM4ce5gv6QOgHi3DaqmBHINn6SDfJ
         YiIG278xG2UgDDLwy6x5Ve3ekbOSeV4ke0NpZIX2dGeaOFKlXxK9YGQqxbn57E5mdqEE
         MBL5jIejOgBoFuR7NI2VeDKDbQ+Y2ngNsQ/OvVtYd2TRu8RasZrnMUb5mS+nT4vXpX4f
         E2KlLyGjn0v1IK7qvXTQtPHAHVI2cTpnHmbSnd7hlwUFFRhaYFoExkJT4cm/8obng6cX
         qLdoFAWzt0zvimjBQCOLT5VcPNvXhBiwI/84wAJqahoRDkYGLCqJ8iNHqWvNSo6Gaz0I
         UXUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=kYBpcZIKUcFir8yGChy/ul95NfA0WU19TKDTNV+cOmw=;
        b=UdQeN8bwyPNcXbq0fWsrzt6LKACzaKLEkmS/AY6rkNAnAqg+XyPx5HWMo70sIHKqsK
         mQLdxLo3ISqdt4+4oVgLyUe0T4GUboddfXt+scTq9pkUN65ojQeTNyz6HaDVl4xX4MIZ
         OmdG2xokxu3FlgmFf7q5yaqAbpMbfPl8HyPKquowzgisHgrBYZoEDP3HSbcWBdDIQQuI
         rOgbUi7JsE17TpjYdn5prpvfuhc9w1u7E9mO0FOy6vDYDiN9ALmKUJQ94YlbXdqvpFZ1
         YjF22ZdyMX0dwJnufGPHwqEnZQarG4A36RQBXTYdvsGcadPjXC8xKKAsHUtGWkwuinOe
         dRfg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=kSPHLFXV;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d32 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kYBpcZIKUcFir8yGChy/ul95NfA0WU19TKDTNV+cOmw=;
        b=AsrlsVqMk0N9UAIdIanjR4GZhmZY+ZzjG9DePw19ly5op5SoKHXHsvcX0m33W2K7CX
         P6J7c/Ns8TPED1i11SVIO+JEB4/RkLQEpnP4AACejtZLiqgL1Pc+4bKiai8iXwXQW2k1
         nqKPliwxMcuRxi0+fYgKCDq4lrjNRE/3i+amdjroYS9mwr12l3+LNoK1sC7/G+DGhgfd
         NmfUuJh5rf4VOG85HoojdwhzDLH5FC0r743TrCapg4tiYU7zpVshLypPDiBhbujdr6Mm
         oRszDUUbcyvVahkW7XmtN5xjF08KJlGeaXsnUIPyjPQ4qgz9leZCj5tG7toev3dRWtx/
         hRRg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kYBpcZIKUcFir8yGChy/ul95NfA0WU19TKDTNV+cOmw=;
        b=VBDPUgX1HpYvhgV7NFtMHSN8nlecycZP9ZEnPkMcvQm7yD8bvpYxF6JAttAf866QKO
         aIqHxOaKCUHSisapg8YzET2dC1IHj6DkNz4Jp4KzXJYYoIATCijFPLmzuBEUMwSlcNsU
         zb8PBlXtSSXHRsrnp+RGCoXrJ122mJwLCKH2W9iqoYS9Y8fOzcXJF5fro/zX1DJZnLc5
         x+7h9ePs9suSkSgot3W+oebvNTTMiyFMVcmoevUKnMtFcSwE14T91HARQ8h7sxh94rpY
         66dJeA/L9o6Rubm64bBr6nRCpkKoS9sbA87AR2obaIybHsE6RSs1sovvxOtLMy3WsDrA
         98Jw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kYBpcZIKUcFir8yGChy/ul95NfA0WU19TKDTNV+cOmw=;
        b=IOhE+YkV++GQlhQf5KAA+jo3FzPDKZhKyF9v/wQHxOnRT6k5IcB8jsY1UM3LEHiltE
         qRbovlOb685g3l+Jbd1+XDjD498ZWwRf6+IJs/opwp3xKIvF+tLjRIEnQP8afgYiQVgM
         TnSyG/xAq7ZxMx8SSapvgL4o3KOXyigColjGGkALXuIF6m2d3L1rcCagOMkk5ao93gt5
         DufJ3UYStQR/S9P7MPIsny9Yg7od5GQejHEKBcKsOPAOB8BKtO44RF13potU+vADA3JX
         6hyhZZ7wNLpOZsc/yZfPspjuSPY7R5CfQUOqvUfPH9MW7B9ZTUuBAKAaH0BVydHJHKuW
         N3cg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533CKGsE58pcz6czH82OmOauhA3WBzYhrYvGRwGnVXzixRD5Yv3q
	bGn4/AjJO7H3VXGzlEt4Mwo=
X-Google-Smtp-Source: ABdhPJzmUDq9ZQLnEh5NagFfPYbJyeBs/rLcpRFj6rIJoJSIiTiOVtqgJzSiwW7eGclU3yvkMVOxfA==
X-Received: by 2002:a92:cd8f:: with SMTP id r15mr5161507ilb.278.1637332578035;
        Fri, 19 Nov 2021 06:36:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1404:: with SMTP id n4ls584917ilo.6.gmail; Fri, 19
 Nov 2021 06:36:17 -0800 (PST)
X-Received: by 2002:a05:6e02:1529:: with SMTP id i9mr5365540ilu.253.1637332577649;
        Fri, 19 Nov 2021 06:36:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637332577; cv=none;
        d=google.com; s=arc-20160816;
        b=F32+3N3uvF/UTZ6ozps4C2rkUfRQfDINs/UzX05eozdaXFI0+s1hotbxVG1ZC0qiPd
         7PzUFzYVITLMOGqEdqKqfuz5zR0r/7bAobHBdNZ/nyUZ2QNPZPTFC0dWMnsSxnEthDR/
         pcH2/ZI3VVjZtn2FmjlHDnaOuFmejB/8iaDvjDUWvSY+qah44ZHSQNncXZ/pvUkHa/MB
         XSAVk5/DyQMOaSqytiRINzde2pW/qZ6pUi8bLsAs3K6fPTtAj3G0Lg5msCaCgZW8cNFn
         kSyRZAuo9ANv0agdUmieeINqzAqqJyyphUTMuz+gSmFQJn+Z9tQfLZubVUwFp34slu/+
         rBRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=n3UlTJrvd9wmoZcXID/TPD0zD7tHGOLcuQUqvmY9UHk=;
        b=az1nt4y2jZ2OmfJyIDz4u8sIvm7iPwPJwyPjm4+jN561+dE/257pTDVJA8RCuwn8BC
         ehGEbI/A2cZYZnuzp145ffGKTayzCHW7eHQbzIeRktQuVzlGou9GMqodm6kSasjWBiuV
         PTe9I8EnRS76k6Dfx7GT/Hpw6HLsP/FtLoVNdqhJ99WTkwk/tdeu0C1XVvHvcduiJk0i
         UdVPGjcRfQ0zbMxzG+RTW3k2ACN/YBtQsJPi73uLUk0o+ampqYwtPfHrQX0flDsShe1E
         5F0sgrucGeBUCyMUIyhn8V8CRoV5MMKqGPtSst6kYQrLOND0U3R4DoqrNXnVVJDiKeVG
         HUjQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=kSPHLFXV;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d32 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd32.google.com (mail-io1-xd32.google.com. [2607:f8b0:4864:20::d32])
        by gmr-mx.google.com with ESMTPS id f19si166259iox.3.2021.11.19.06.36.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Nov 2021 06:36:17 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d32 as permitted sender) client-ip=2607:f8b0:4864:20::d32;
Received: by mail-io1-xd32.google.com with SMTP id c3so13029752iob.6
        for <kasan-dev@googlegroups.com>; Fri, 19 Nov 2021 06:36:17 -0800 (PST)
X-Received: by 2002:a05:6638:2257:: with SMTP id m23mr28211802jas.17.1637332577526;
 Fri, 19 Nov 2021 06:36:17 -0800 (PST)
MIME-Version: 1.0
References: <20211119142219.1519617-1-elver@google.com> <20211119142219.1519617-2-elver@google.com>
In-Reply-To: <20211119142219.1519617-2-elver@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 19 Nov 2021 15:36:06 +0100
Message-ID: <CA+fCnZdKLrniF4ru8G5=hkm4M6YYm3RJz6wFcNqD2hPC8Trj-g@mail.gmail.com>
Subject: Re: [PATCH 2/2] kasan: test: add test case for double-kmem_cache_destroy()
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Christoph Lameter <cl@linux.com>, 
	Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=kSPHLFXV;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d32
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Fri, Nov 19, 2021 at 3:22 PM Marco Elver <elver@google.com> wrote:
>
> Add a test case for double-kmem_cache_destroy() detection.
>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  lib/test_kasan.c | 11 +++++++++++
>  1 file changed, 11 insertions(+)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 40f7274297c1..4da4b214ed06 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -866,6 +866,16 @@ static void kmem_cache_invalid_free(struct kunit *test)
>         kmem_cache_destroy(cache);
>  }
>
> +static void kmem_cache_double_destroy(struct kunit *test)
> +{
> +       struct kmem_cache *cache;
> +
> +       cache = kmem_cache_create("test_cache", 200, 0, 0, NULL);
> +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
> +       kmem_cache_destroy(cache);
> +       KUNIT_EXPECT_KASAN_FAIL(test, kmem_cache_destroy(cache));
> +}
> +
>  static void kasan_memchr(struct kunit *test)
>  {
>         char *ptr;
> @@ -1183,6 +1193,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
>         KUNIT_CASE(ksize_uaf),
>         KUNIT_CASE(kmem_cache_double_free),
>         KUNIT_CASE(kmem_cache_invalid_free),
> +       KUNIT_CASE(kmem_cache_double_destroy),
>         KUNIT_CASE(kasan_memchr),
>         KUNIT_CASE(kasan_memcmp),
>         KUNIT_CASE(kasan_strings),
> --
> 2.34.0.rc2.393.gf8c9666880-goog
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdKLrniF4ru8G5%3Dhkm4M6YYm3RJz6wFcNqD2hPC8Trj-g%40mail.gmail.com.

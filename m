Return-Path: <kasan-dev+bncBD2OFJ5QSEDRBSPNQ2IAMGQEEGYPZTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7921B4ACCBB
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Feb 2022 01:18:18 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id c4-20020a2e6804000000b00243ab1994c5sf5198009lja.9
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Feb 2022 16:18:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644279498; cv=pass;
        d=google.com; s=arc-20160816;
        b=mXV1GcvoiAyIZGBsonTz3e+Io6+WKHYcN0jtfaw2Cd6EfmsTQEd8uk3B/pmRUd7u1R
         bkss6P1+UjzL/Z7VynU8fH++rUvjjgY6vi5MNPszydtRncuyoft4I8/3FAa2jUTBHKBn
         iiUAkYpC7En6CxIhvZRfWa0JzBVJrTiSfp20T2gTL5syvmBgCDDlS0imiOAZAtv2htT0
         iqbeB1qbjVZvo5SrF5INgxxDhqkIPWdsFs5WkspTyLqWW/D9vjYvuwDF1hx9da4+/TcM
         9uT8jhlsBrsNSghFe0SCtS/+RwSAk1wrjBGMinxMp5fIrhwC0ZC8WjhYuraAToAsVBPc
         FM1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=2Rg6XLHAEgJxtSWdKzYGrPayYmEV7NehjIKQHxhOZLM=;
        b=zu2fFuqtQylnCF3nJh3oLY9MoPQk4crDQZwK6UjnJkbEG110D070W9oWjcogigcFRk
         Ema+QOk0A65077VGVQXNscqcuJap2i9FtLFsyn3Lv+5X870knu1sllHmOW7t1qu7cJ8L
         oyjX9ihYaoVR535Gn8GQJ0GJNTan95MJV41XaWl0+8mbaoMW1cyag5/q0yUZoQFZUuZk
         gMHD9nHVp3mfgPf8l0XZvxKJn2sfHlGKBNO97Jng6o/exP7iAjxVCOoslephPlm7ZCiT
         0wg1l4ABOh1W9dhne+ibzpOkgjPw+3/nc+71Kkvkyf9DX0XzQ+os3wSFO1j55EjjVBkS
         mepw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HsUaZkqH;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::62c as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2Rg6XLHAEgJxtSWdKzYGrPayYmEV7NehjIKQHxhOZLM=;
        b=UPZXv5wa2lgddbTyeTz7y/Ld5tGwbU3aFar4bLGzrndR+OzXayck2zhLH8L/ThIxKM
         5Mgjmb+ePWACX/l2vHOvCmAqfxpp25CD5oBe7VTJ6rxM0hBfIuQbazAxxFRBHO82Qi4F
         g63XLtxlqNy8LEbGOEru4lZr01QsuNR6iJzpwoViXYdqxRJi98r5iuLmRVqzecLpLWSL
         tVnbVMjx0q1ppaLM/oU3UkL3+/rZBGhw+6oSeUIKsJRHk3sRJFk7cMPiyj7sxvE9VbSg
         kgEC1EyH202K7ailsjfI6E02FOaJ419MiQSWEngl1NNbRKvWTwiO10NEoOKO7XrQkQgg
         ggVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2Rg6XLHAEgJxtSWdKzYGrPayYmEV7NehjIKQHxhOZLM=;
        b=VIGsVJA1Ys5/ftME/yqhNCkiG0FY9iIy4y+/JBlMdUZdo5pRDACAr99lmbSNmwiVPG
         TYc3sFr8Ql8Q9wkdKLjJwrB+Uw1yq2AZ4DXAD45GUu6geM0vbupUp3b9mdUUTY94zVCz
         8q21qAnp6q4BYX47RWjxhZOEuTp7mmEyIaL4oxoZrXmubfB64jV/vKTHfbUJbncCzFFv
         z6x04NL8NYMoECBb91ppfsxVFUBqu0HLQII+sQKFfGRU98RIcINkdoNNt9k3naa26q+H
         o6bgc1Xs0Cj7UUqWFlirFrmhcOXNFkM8ooGQTDmfbxQSMwJXjRZAQn22y9MF0HBpBXGq
         KarA==
X-Gm-Message-State: AOAM530dvlTHG5c/tJKWOYmgTsahPQDKNC/OpkJgr2BC1Lfe2OeR1/BK
	ltjc61GvKE7OuFtln7JGj+k=
X-Google-Smtp-Source: ABdhPJyLEUaNSJl6LbBvaHAjBW/XsAIbsjsGuRDeOMgqQ29r/YGXCpySEnrWXsgsThA6jyZSciZ5vg==
X-Received: by 2002:a05:6512:4016:: with SMTP id br22mr1287747lfb.683.1644279498068;
        Mon, 07 Feb 2022 16:18:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:2128:: with SMTP id a40ls1654721ljq.9.gmail; Mon,
 07 Feb 2022 16:18:17 -0800 (PST)
X-Received: by 2002:a2e:5804:: with SMTP id m4mr1225614ljb.437.1644279497117;
        Mon, 07 Feb 2022 16:18:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644279497; cv=none;
        d=google.com; s=arc-20160816;
        b=B0mtCYWuDWtGSgu72QHVUe8BvmZKwBcmHASN1XaEi5jMIP5ws4EZvzHZw2l7Ei1ZlZ
         sFZsgVJllHaFEmu2qk3u3Cim4FZMpQb//mMZ7BELuUFpe3EpPz2AYESJOz7O/CalaMPm
         fTudQnX5JJRowEmOWVQ3BmatavgczyE7Of9AOF5dTYA2Afcej4/J8CrgfyPoSrsoPcxG
         vPwyUcRrH+TTxetbondi1OuNu5c4HD/+SufuYOBd+uPkSO7CMsqurtPFwxzKC5yOA4XV
         qfSTRQYff+qs1EoLGym5htMrFW0MwIkdt7ewlQrCe3Ldo8eehM0swHd9uZmYPEQMs4bB
         exCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=eIx1vqQAPUu8LMm53/zUpJw9Sxu1UeMfE4UVerJwTWM=;
        b=Z3JttOwzIF0tz3OmgHckYb7rQq+W6WdxDXhF9qqjAxSg7YShX4cpCAYHmk0nMGlD9K
         v001GGQ+uMrkcO+eSlbiyZV3diIUI1+72Vtub+uEFlsWtNqtAJ1l2UAGXBYAY7aUF7wM
         1Vqm5p2j8MO5F/AjNxehFZUMol/0hlPivxyGqN20K4RPB9F4moSVWqt73SlQwnDQHy1w
         gg1pS/B+EevtDCFqnPr/t095WEZp77AEtI6jOi1kWRbkiS5akn9lBb53sZfedD/dXmaa
         cZ7U6aPf27He7eEsevEWFtS+W4vFBFSSag0Imze7YJN2NtxrEDuZiZMGfAq/sPn+4LE+
         7C5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HsUaZkqH;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::62c as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x62c.google.com (mail-ej1-x62c.google.com. [2a00:1450:4864:20::62c])
        by gmr-mx.google.com with ESMTPS id l17si550883lje.5.2022.02.07.16.18.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Feb 2022 16:18:17 -0800 (PST)
Received-SPF: pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::62c as permitted sender) client-ip=2a00:1450:4864:20::62c;
Received: by mail-ej1-x62c.google.com with SMTP id m4so47140320ejb.9
        for <kasan-dev@googlegroups.com>; Mon, 07 Feb 2022 16:18:17 -0800 (PST)
X-Received: by 2002:a17:907:6e28:: with SMTP id sd40mr1599073ejc.170.1644279496489;
 Mon, 07 Feb 2022 16:18:16 -0800 (PST)
MIME-Version: 1.0
References: <20220207211144.1948690-1-ribalda@chromium.org> <20220207211144.1948690-6-ribalda@chromium.org>
In-Reply-To: <20220207211144.1948690-6-ribalda@chromium.org>
From: "'Daniel Latypov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Feb 2022 16:18:05 -0800
Message-ID: <CAGS_qxrK7TBLkoi9ztSJXcoQ+_Z0YC_HWmrp++2C1mc9ierOEg@mail.gmail.com>
Subject: Re: [PATCH v3 6/6] apparmor: test: Use NULL macros
To: Ricardo Ribalda <ribalda@chromium.org>
Cc: kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org, Brendan Higgins <brendanhiggins@google.com>, 
	Mika Westerberg <mika.westerberg@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dlatypov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=HsUaZkqH;       spf=pass
 (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::62c
 as permitted sender) smtp.mailfrom=dlatypov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Daniel Latypov <dlatypov@google.com>
Reply-To: Daniel Latypov <dlatypov@google.com>
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

On Mon, Feb 7, 2022 at 1:11 PM Ricardo Ribalda <ribalda@chromium.org> wrote:
>
> Replace the PTR_EQ NULL checks with the more idiomatic and specific NULL
> macros.
>
> Signed-off-by: Ricardo Ribalda <ribalda@chromium.org>

Acked-by: Daniel Latypov <dlatypov@google.com>

> ---
>  security/apparmor/policy_unpack_test.c | 6 +++---
>  1 file changed, 3 insertions(+), 3 deletions(-)
>
> diff --git a/security/apparmor/policy_unpack_test.c b/security/apparmor/policy_unpack_test.c
> index 533137f45361..5c18d2f19862 100644
> --- a/security/apparmor/policy_unpack_test.c
> +++ b/security/apparmor/policy_unpack_test.c
> @@ -313,7 +313,7 @@ static void policy_unpack_test_unpack_strdup_out_of_bounds(struct kunit *test)
>         size = unpack_strdup(puf->e, &string, TEST_STRING_NAME);
>
>         KUNIT_EXPECT_EQ(test, size, 0);
> -       KUNIT_EXPECT_PTR_EQ(test, string, (char *)NULL);
> +       KUNIT_EXPECT_NULL(test, string);
>         KUNIT_EXPECT_PTR_EQ(test, puf->e->pos, start);
>  }
>
> @@ -409,7 +409,7 @@ static void policy_unpack_test_unpack_u16_chunk_out_of_bounds_1(
>         size = unpack_u16_chunk(puf->e, &chunk);
>
>         KUNIT_EXPECT_EQ(test, size, (size_t)0);
> -       KUNIT_EXPECT_PTR_EQ(test, chunk, (char *)NULL);
> +       KUNIT_EXPECT_NULL(test, chunk);
>         KUNIT_EXPECT_PTR_EQ(test, puf->e->pos, puf->e->end - 1);
>  }
>
> @@ -431,7 +431,7 @@ static void policy_unpack_test_unpack_u16_chunk_out_of_bounds_2(
>         size = unpack_u16_chunk(puf->e, &chunk);
>
>         KUNIT_EXPECT_EQ(test, size, (size_t)0);
> -       KUNIT_EXPECT_PTR_EQ(test, chunk, (char *)NULL);
> +       KUNIT_EXPECT_NULL(test, chunk);
>         KUNIT_EXPECT_PTR_EQ(test, puf->e->pos, puf->e->start + TEST_U16_OFFSET);
>  }
>
> --
> 2.35.0.263.gb82422642f-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAGS_qxrK7TBLkoi9ztSJXcoQ%2B_Z0YC_HWmrp%2B%2B2C1mc9ierOEg%40mail.gmail.com.

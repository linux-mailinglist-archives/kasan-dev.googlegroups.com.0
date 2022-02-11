Return-Path: <kasan-dev+bncBCR45TXBS4JBBIHLTCIAMGQEMWU4TBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 19CD24B22C7
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Feb 2022 11:08:33 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id n9-20020a2e82c9000000b002435af2e8b9sf3826570ljh.20
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Feb 2022 02:08:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644574112; cv=pass;
        d=google.com; s=arc-20160816;
        b=VAlVhzNFfbJw3Nn5WLht+NoKSHRtFMcUeUcdjv8vZLqhR+Vuloik9eCPsHmc2Hoe2x
         BysJLkbc3OMxvX1NoUjC9A6uGCiH0dgSOstS4slEhZF2ggQv+VSB4dgSAMqTs8tNJSeA
         /Y65VtbibtUnqS9zJ4VXzudbLJdlxP5ZrlQFNOSEZIV0QWYk8To/ASEBvY/ZBCM2al5W
         GM7NnzsHupXmdvL1Y4vrSqdSp32jI4X/Ef/MYeMsNGdi3QqL0R/1oDp8SdV32VL6H5yj
         5U457733am+2EQgfAnNKLuQ2kqewA15C9XuZu2F5HHhTC5lYiExebtFfn25o6k/gKwZx
         6kmw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:organization:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=FQJmEugObr7rSyFolm2+2SFcR3BnySWcrYh0q9i3qZw=;
        b=x4+C+c8VAuiNwIi5V8Dd9hi8If3zNTElCiICZRgIwmoIO+q4zA2RlfM4bRMKVhHKk+
         i9Hzo5m9yTfGV8ZnDWPzbO9kj3Vd/1zWRvWrGyEd9FHq/b1wwpEV4kSwA5bN/1XoVJzi
         p46xx7s9HHKly4b+BnbhOqbYxh8r/0M1RpVQ6UspuKAAVQ4Zubg1nVbsGHYUCokIWZms
         zV75HQYAOniE5UUSn4kqtd3ZWF9LmQSRyqJ6hf/hgIkOZUatDtLaNlCzUj4Q9R9O2hO+
         zF2jD78sX/xc5SCI4rX0+7EWPnINYTAKQ462snhTJD88CvWBMtQ0wsDEFw9sfpKD41f5
         V3Pg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=hRqtaNLc;
       spf=pass (google.com: best guess record for domain of mika.westerberg@linux.intel.com designates 192.55.52.151 as permitted sender) smtp.mailfrom=mika.westerberg@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:organization:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FQJmEugObr7rSyFolm2+2SFcR3BnySWcrYh0q9i3qZw=;
        b=tS9RQBBGxDbJDhkvsj3mrpkh4NO1sRYQFzxRLSUHLmGtuec8WXrjnB5Ct4nuvWsYgq
         H6cJQZWp4XGqTddV+B8DFDj4J8cIFcfYtApZKYopoS1vv1HISFo0OBm/xMQ4zeqNMXHI
         T/8Yft+EHaOE5qlfh6yGu1X0KQ57Qe3H+M8zoQnl45/71G3jCYLBSL+oshVaNJF8VtMk
         ltCm7w6z/e9Libb2EjByooQq/BIGkRYDUw9scnM3XMe741kX8uL560yX+9S6c7cXWYyP
         ejnLCNPZufslEuarTTZ8e8BijJj5ryMqG6F2TtyNREifGHrW1R6Z5z7puwKBQyqJYUyw
         YA/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :organization:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FQJmEugObr7rSyFolm2+2SFcR3BnySWcrYh0q9i3qZw=;
        b=qhvaX9PXCI1UNHzp26wse/fVAXGtNZGknbckTZbHwOVlM/31bqQ1ibfGoGfNDWwuD8
         GFrn/qHV4/m62m/jLNNKs9ib2yKARKBnTSei7gUmb5NxWGeS1bOa+d/g9lVKT+RFIGC9
         aaRfzta01caEdhDyZFaDfs1b+OEGKImpCUoxLdKFi7UX2wREPyzA5jWg2pl8mHhprJBu
         IbtTWkwra6K3YxihuF1JGECMAQxs1TgfcdAHn2OCfeZgpLUddr2k9DOl0gNCF5p9dQrF
         cZz2gOvvoIBnmfuUtVLIsYf0Gbd4zQCpaKWUlGFvaaEZ7CXZKJbIQ7PzDQmsURV9LPef
         0qLA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533hFBX1M08gc0G9Nj99Y60Jgdf1mWfBKMvBJpd5bEDFJiv8/n0i
	UbwbqW++MjsXFcU56xm1sQE=
X-Google-Smtp-Source: ABdhPJxnNSrh99flcToIpp6QqpVDwWPhIWPQ+UwpCnoH1d5YVLSZ0eyP2SKSEWWQEkAcWgI5Q7nUBA==
X-Received: by 2002:a2e:3903:: with SMTP id g3mr579539lja.76.1644574112509;
        Fri, 11 Feb 2022 02:08:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:98b:: with SMTP id b11ls1424199ljq.7.gmail; Fri, 11
 Feb 2022 02:08:31 -0800 (PST)
X-Received: by 2002:a05:651c:212a:: with SMTP id a42mr577693ljq.100.1644574111258;
        Fri, 11 Feb 2022 02:08:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644574111; cv=none;
        d=google.com; s=arc-20160816;
        b=A8OJ0VakXao5gv8JrEYgHixx9msmL0HVD9xk2czlPGOZsTZh2tcbLo6Xxivax1GlgL
         h7pbXf8PUqqIatIsRkqqLMZXcAqXB6SndSt2Ao1zWESYK0HJP8XDxSiNjj+qpewZXOwd
         6uGTkKWR3UpfqFzMVreczcLc4wAe8nznAlePRJx+0maEv+WF1wgJrS3vyRIR1tg+O0QG
         8lodZ+H6jC5kLvfI9VjB5I3CTR3jv42KX38KFK+y2vpHyA4S+07hA6Nzq+2BQ92UGcr3
         iz8tOnNG94OMZvyJB+Jj6T6Hkrw5ogxMLnGduKZQu5sh3XUzo8HPFwIIHahbHIlkIWBv
         JwyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=organization:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=pavljXryT1YJsVhMYkHrsX0h1v9vChGlrtlhEz5VPh4=;
        b=Lymka+5wh9w7sfz2ApoPjGTWkAyONDLpITqWyjtQzXWtD2VDx+WQJvXRcNSNs8Liut
         RrYZyR649FPhgTFg2W345FZW5bLpcRdWz1sxsPVudXb0wU4nvVXSISAUvzRek169bQLk
         NVl5DkFRyF8IdCO+dD9+9jVdz6ly05dOJcI068behgkbwYaHharYyGU4gj6rTPphXo2W
         ZKNb9cY3K+OTPX+i2sJwiA/bNpBtmTPwPURU+hWh+AajfsvZNcBYqOgzk4q4kf76HngB
         VnozTJzum5xKWEYiezzhU9X+dMe7Wch7vWFugcULNq2fSnJQmV6zQaYkCDddOYqGPQkb
         FG4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=hRqtaNLc;
       spf=pass (google.com: best guess record for domain of mika.westerberg@linux.intel.com designates 192.55.52.151 as permitted sender) smtp.mailfrom=mika.westerberg@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga17.intel.com (mga17.intel.com. [192.55.52.151])
        by gmr-mx.google.com with ESMTPS id g7si385344lfr.7.2022.02.11.02.08.30
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 11 Feb 2022 02:08:31 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of mika.westerberg@linux.intel.com designates 192.55.52.151 as permitted sender) client-ip=192.55.52.151;
X-IronPort-AV: E=McAfee;i="6200,9189,10254"; a="230347255"
X-IronPort-AV: E=Sophos;i="5.88,360,1635231600"; 
   d="scan'208";a="230347255"
Received: from orsmga003.jf.intel.com ([10.7.209.27])
  by fmsmga107.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 11 Feb 2022 02:08:28 -0800
X-IronPort-AV: E=Sophos;i="5.88,360,1635231600"; 
   d="scan'208";a="483271617"
Received: from lahna.fi.intel.com (HELO lahna) ([10.237.72.162])
  by orsmga003-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 11 Feb 2022 02:08:25 -0800
Received: by lahna (sSMTP sendmail emulation); Fri, 11 Feb 2022 12:08:23 +0200
Date: Fri, 11 Feb 2022 12:08:23 +0200
From: Mika Westerberg <mika.westerberg@linux.intel.com>
To: Ricardo Ribalda <ribalda@chromium.org>
Cc: kunit-dev@googlegroups.com, kasan-dev@googlegroups.com,
	linux-kselftest@vger.kernel.org,
	Brendan Higgins <brendanhiggins@google.com>,
	Daniel Latypov <dlatypov@google.com>
Subject: Re: [PATCH v5 3/6] thunderbolt: test: use NULL macros
Message-ID: <YgY1lzA20zyFcVi3@lahna>
References: <20220211094133.265066-1-ribalda@chromium.org>
 <20220211094133.265066-3-ribalda@chromium.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220211094133.265066-3-ribalda@chromium.org>
Organization: Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
X-Original-Sender: mika.westerberg@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=hRqtaNLc;       spf=pass
 (google.com: best guess record for domain of mika.westerberg@linux.intel.com
 designates 192.55.52.151 as permitted sender) smtp.mailfrom=mika.westerberg@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

Hi,

On Fri, Feb 11, 2022 at 10:41:30AM +0100, Ricardo Ribalda wrote:
> Replace the NULL checks with the more specific and idiomatic NULL macros.
> 
> Acked-by: Daniel Latypov <dlatypov@google.com>
> Signed-off-by: Ricardo Ribalda <ribalda@chromium.org>
> ---

...

> @@ -2496,50 +2496,50 @@ static void tb_test_property_parse(struct kunit *test)
>  	struct tb_property *p;
>  
>  	dir = tb_property_parse_dir(root_directory, ARRAY_SIZE(root_directory));
> -	KUNIT_ASSERT_TRUE(test, dir != NULL);
> +	KUNIT_ASSERT_NOT_NULL(test, dir);
>  
>  	p = tb_property_find(dir, "foo", TB_PROPERTY_TYPE_TEXT);
> -	KUNIT_ASSERT_TRUE(test, !p);
> +	KUNIT_ASSERT_NOT_NULL(test, p);

This should be KUNIT_ASSERT_NULL(test, p) as we specifically want to
check that the property does not exist (!p is same as p == NULL).

>  	p = tb_property_find(dir, "vendorid", TB_PROPERTY_TYPE_TEXT);
> -	KUNIT_ASSERT_TRUE(test, p != NULL);
> +	KUNIT_ASSERT_NOT_NULL(test, p);
>  	KUNIT_EXPECT_STREQ(test, p->value.text, "Apple Inc.");
>  
>  	p = tb_property_find(dir, "vendorid", TB_PROPERTY_TYPE_VALUE);
> -	KUNIT_ASSERT_TRUE(test, p != NULL);
> +	KUNIT_ASSERT_NOT_NULL(test, p);
>  	KUNIT_EXPECT_EQ(test, p->value.immediate, 0xa27);
>  
>  	p = tb_property_find(dir, "deviceid", TB_PROPERTY_TYPE_TEXT);
> -	KUNIT_ASSERT_TRUE(test, p != NULL);
> +	KUNIT_ASSERT_NOT_NULL(test, p);
>  	KUNIT_EXPECT_STREQ(test, p->value.text, "Macintosh");
>  
>  	p = tb_property_find(dir, "deviceid", TB_PROPERTY_TYPE_VALUE);
> -	KUNIT_ASSERT_TRUE(test, p != NULL);
> +	KUNIT_ASSERT_NOT_NULL(test, p);
>  	KUNIT_EXPECT_EQ(test, p->value.immediate, 0xa);
>  
>  	p = tb_property_find(dir, "missing", TB_PROPERTY_TYPE_DIRECTORY);
> -	KUNIT_ASSERT_TRUE(test, !p);
> +	KUNIT_ASSERT_NOT_NULL(test, p);

Ditto here.

With those fixed (please also run the tests if possible to see that they
still pass) you can add,

Acked-by: Mika Westerberg <mika.westerberg@linux.intel.com>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YgY1lzA20zyFcVi3%40lahna.

Return-Path: <kasan-dev+bncBC7OBJGL2MHBBE4JQ6HAMGQEO6XPEOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id EB40447BF70
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Dec 2021 13:12:03 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id v19-20020a056402349300b003f7eba50675sf10293901edc.12
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Dec 2021 04:12:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640088723; cv=pass;
        d=google.com; s=arc-20160816;
        b=oRHmDvzU0loluupDaiXwzkoMA3tJGI+093fds3GYDKDm/tq97Tp4Ws3aJ8Lt2Gv9fb
         qsCW92+QI8wywnlq79FL4bMJCS9brZ7MBmjtizvaBZLOji5ebdPS6mz58jrroWgbQeJV
         7PClM9uasVpl7QqP6rm6CDRkqt/MbUaOs+KbFFCs96KUW9ldFaTKSRpz+tz0NVVyxY0/
         0I+KXFvFwzqbz6OTm47g8C67z1hyNfcNOYjX3Np91er+FHls3sB68NqFzyJmWfLRSV8C
         Wg4LvrDzfEj+ntAoS/ybUm5dDwGQaqpjUCSVZ5ujCW9s3PtmXpgKlS4Ye0JMQv5TQOYj
         y2mA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=9u1rECOWHkqGL8FGTfge45n8fjNrqH0l2EDqZCJeiGA=;
        b=PMbLqsOk7L/PazPcpD8u3GK8g7x1vcbU8R9EQYvicqCZI4P/kzMbDkQnFLuyRI4qda
         zqTI1QUJ8zjoYRuAMV6Iv3Vs8qP6lYcmivpR38Bc+av1zxioJu/xKQf9f6UAtEus9yp/
         bHSCK9U1v+NQVmfHxb5bQWZcr+RBgBr9IvUqS90s2XXpvDJQhHfr1AeTfYHKK9EHvaBk
         9TuUjYNzjw6Lq3QWZpK9ElRmyUj1LsYms5fqM9vrGKmGvR0i/wGdkuRcmdlVjuFapKtB
         vn4FkHq7bGAeApvgCIMMxpmZjURW4Lh/uUVFiL3iA3ZMK8rJzv1FtUPfAaOHvMlD2g5U
         PQKQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rXXpkxvA;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=9u1rECOWHkqGL8FGTfge45n8fjNrqH0l2EDqZCJeiGA=;
        b=Sk7tUUdxqwIz3jXlzCt6yhjxEklbHmX1KGS1Oz7lHb02jhnRxEnAee0O4AyVVvLiOS
         CmwrMcuferXsIvNvPzeVdJA91e5qoKjXGsrPwRDQUA/Cowb4jnBkY3kLNAO8QYLRAZNN
         DZGWz9DXCOUo8STeWjTvbgkt2bzCmq4wiIS9rKF9S/trbtjHOstQg48kMCuz51C1Cw8Z
         qykH6LfMslcQj46hCzjdFBGVZM/bh62iT9q8GUCVqPa/mfQI4gXaoaxSSFzwOhZWf3h8
         IkyCIAbdpgqSgKnOLultV6udJXSmPBsIiOD6MB+OiEazvEbDASXm56cAECnc9yq5sfWS
         qD+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9u1rECOWHkqGL8FGTfge45n8fjNrqH0l2EDqZCJeiGA=;
        b=tiGnQG2n9h2WqafZ360ECCJiE0hfMbI6uCwdX3UlFgBFi459VFt+gCVrXGn+GMVv7p
         V/Pd/UNJa3w2kxFDvRt1kyzE4mMSSMRqQ4XhdOaqmroMsnEUEXKPapyM+ScERmiKt/+h
         1/Q00kBTsI3lSiJ19uMg4vtlAPfJA/yNv4rE+oV5Pc3N+tRnBNWHTfrI/rFRGbk7I6DL
         hIqpouK4ACRKCu7V33/MjeyrIvWU5DGmKCp0mX/6nP4rmJilY4COdInCgpFG6D8TxhKS
         nUW83nBi3kAShaf6GaO+8w9jM9DK8Hn76qZfnEjrgCtywm1/Jazy2c+BizS3kwSQGhLU
         lWOg==
X-Gm-Message-State: AOAM533OFhxjno0Eb3Z59XWdNvn2OBt3k+dsPUP+/myyV+qopl0KKRDN
	xZ5SPv4DwJp3MjmNy/rNSkA=
X-Google-Smtp-Source: ABdhPJxdaGCGRb7yUiQSWt+SBuSd7miMQVAhoZnLFb0iHA+llztTzAWXm1UXqxf8Hjo8gPwN+bRpqQ==
X-Received: by 2002:a17:906:794f:: with SMTP id l15mr2430700ejo.488.1640088723574;
        Tue, 21 Dec 2021 04:12:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:8693:: with SMTP id qa19ls2103688ejc.8.gmail; Tue,
 21 Dec 2021 04:12:02 -0800 (PST)
X-Received: by 2002:a17:907:2da6:: with SMTP id gt38mr2524367ejc.536.1640088722547;
        Tue, 21 Dec 2021 04:12:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640088722; cv=none;
        d=google.com; s=arc-20160816;
        b=ovT2TQD3aALJnOXSpMnRAuJdwVQREK+OX35ZZGrbbXphvG4igUTvy05b5WLHceEfDo
         GppG5intGqsqE7La2wXXU6ReOMsu+IGv8x5hyVj8DnZ7FSCLEGPIs8l5GLSvdAb/vVex
         hcQDZZEDFuUGnFs1Le9WGJvEMDp2izovEaUp0fel1PMEsL3nGW/WfQcsCturRlwAQSiG
         vaqKfN73XuaNlPKXtUPiKGxwkubtzFHy5rbf3N+2WXIAvZsiiW2ED/cqr0nYxSioSXFf
         TnWQT6n6Y/SijTUGnO5de68XxrN1FRJguGDDrpYmapPV+l4FBipK6uLxJeGbYv8BpVCn
         tO0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=jfaFJc8Cz1U41Grmp9dApUf6heZ4GsGx9TaK2/L8KJ8=;
        b=0h2TBoKZFO7Z2Cazhuyna9TmU0sENbh5xzVBGFA2NR5BIzj3gzJyofOeXM7lOOZhTE
         KRJAEb4CxK38mzDCZVe8Flvk+yaUOoKEJgUU6SNmgjf81vf7c5z+DS3YqNn2TWcvPvsy
         NGM1cyRnLk1m4RdYJSi3Y5N10QMw5ZeZiQjCVZ8I0NZx3jQ7XyObUIlvOgyMsK/wWVu7
         /GdekAlhDSi3K5rteZBEkP8ytj8pi8iUwkJXh+EvLPnQ5MxR1Ly5WZU1hi81SZ9ygEMK
         YBct4xBQ7qrmYKBn690N04mIpCcXkSnsam9e5/BpFlOFcif0B0kWwFV6CHHYdU8ucD2C
         y92w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rXXpkxvA;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42d.google.com (mail-wr1-x42d.google.com. [2a00:1450:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id fl21si1115121ejc.0.2021.12.21.04.12.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Dec 2021 04:12:02 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42d as permitted sender) client-ip=2a00:1450:4864:20::42d;
Received: by mail-wr1-x42d.google.com with SMTP id a9so26470945wrr.8
        for <kasan-dev@googlegroups.com>; Tue, 21 Dec 2021 04:12:02 -0800 (PST)
X-Received: by 2002:adf:f54e:: with SMTP id j14mr2402039wrp.442.1640088722221;
        Tue, 21 Dec 2021 04:12:02 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:87ff:799:2072:8808])
        by smtp.gmail.com with ESMTPSA id o12sm17642260wrv.76.2021.12.21.04.12.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 21 Dec 2021 04:12:01 -0800 (PST)
Date: Tue, 21 Dec 2021 13:11:56 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>, linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH mm v4 29/39] kasan, page_alloc: allow skipping memory
 init for HW_TAGS
Message-ID: <YcHEjERoiqJTKmsZ@elver.google.com>
References: <cover.1640036051.git.andreyknvl@google.com>
 <dea9eb126793544650ff433612016016070ceb52.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <dea9eb126793544650ff433612016016070ceb52.1640036051.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=rXXpkxvA;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42d as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, Dec 20, 2021 at 11:02PM +0100, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
[...]
> +static inline bool should_skip_init(gfp_t flags)
> +{
> +	/* Don't skip if a software KASAN mode is enabled. */
> +	if (IS_ENABLED(CONFIG_KASAN_GENERIC) ||
> +	    IS_ENABLED(CONFIG_KASAN_SW_TAGS))
> +		return false;
> +
> +	/* Don't skip, if hardware tag-based KASAN is not enabled. */
> +	if (!kasan_hw_tags_enabled())
> +		return false;

Why is the IS_ENABLED(CONFIG_KASAN_{GENERIC,SW_TAGS}) check above
required? Isn't kasan_hw_tags_enabled() always false if one of those is
configured?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YcHEjERoiqJTKmsZ%40elver.google.com.

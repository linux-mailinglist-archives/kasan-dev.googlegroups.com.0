Return-Path: <kasan-dev+bncBCG6FGHT7ALRB7NORX3QKGQEWPQTBZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 555AA1F76AB
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Jun 2020 12:22:54 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id d17sf1445211ljo.6
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Jun 2020 03:22:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591957373; cv=pass;
        d=google.com; s=arc-20160816;
        b=fgsQFBSzN/1GIxbmFPMpO5sJkoeNYXzvan6+iFFxleEde9NmDAr00/BaFHoKW+MSKy
         u2xQqVaHkxCJ/VEFM2ILhVTDIYXHd2iMQaVsvzK/HfRKaCD1vyLBBf1eqkSoMinL9xq0
         sYPZ/y8ZZyvksWSPjjQWquLX0AaQmBgkNKjnvrbF+cikcQnBlK2jtGw3EvmWZ05nNoSy
         bangWsXsRtvGqt8gqNZombB71UtmkwgnUn9xY7QU8ZwWp23kecuhFJMMgJ0z0O7zgpbx
         7uo5PxHCj5pd/4hUORDL2F+XMx8UayC7vAvzTm6fPOCqprQxqFH7XkDdFyv9L3DC5Ceo
         L7Gg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=2lzPa+KLaPZGBgveEzg6XO521xe8koxs0xsagrTtwnQ=;
        b=Av39Gz4FHRkKHSBeiIUlKJU1KhuBAFSIw9UAHYqa5dgJgrG3ZtjgkpbgXG2IV/3qaN
         b7BFG4FFhJ/BvLdFWMM/FJduL6HJ2ibh5QnOT+Olg63B337Z8aEQ35en8wPFG5OkDFYU
         qnapF9hTU0oYLJFtu6llXaYkz1r52EiQ7DIWXgSi+qQ6IQbBmx7t3KXKJZeEYRWZ6CQY
         UkzdGtEN+4eUWoRWUJqao0W/tekaGH++4BmF6bWRTnchUBM8dkTL6V/oQE7+efSNuanY
         WPOSA3UU0Ct8yGfuKKtdrnX5hhbyUzXCwZojB7hqULQbgmsaHxTMpeMVENANqUDLTQJq
         Cl5Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mliska@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=mliska@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2lzPa+KLaPZGBgveEzg6XO521xe8koxs0xsagrTtwnQ=;
        b=gtzitSuUn6mpjK9JLY0QOvlITRviGd675BnpMqd9OXZA38mgjmP7tDXGF4VCcCE2zP
         Eyo1uBnydfCGvgSIL4a4A89iSQqklgmTJnvl0qQFMr8J/bEGO6DPAM3ry5vZFmKS4WW3
         UI7XLEEYjEq6lN2Dzl/PdUMyZodSHuj67DLAnSZjPIqHkxF+B3gAWYUN5TeykdP/dwcl
         4GRGXGiyEV4xfwwjh7pD4GBestX6uXT6mV/8/CB/GS66VwNwqOKcuFcRqItEobPeGWNQ
         krUyf3PlGty+TtOkUJsvFPs60lFx0FbyRqRPWgVo0k4I7lRVsm5Bt7H7H3xktWJ8i5ym
         84cA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=2lzPa+KLaPZGBgveEzg6XO521xe8koxs0xsagrTtwnQ=;
        b=WvRocoDdldsRVs7SA4iWZBmOW6Xg7W72jeeX6WJWOwLmfZOLMqDoMbNNPuC6N+OxWL
         QrdlaAzrpjVsaRBZ0i/YsCbFLBl2NqjdUgjolMipoIbbeT8f6+I/A5Z7+WjKrAjQy2D4
         JeKBOkZK9Tfa2Y9zE1toeVCO3K91UanMArtUy+XbkDSWu6asixUeeXKH+9h9Z3QmET3l
         qRYOe7TW2D7i78Q08CKPjIEvN2Y91w1Sw43Ao+g3UtYFfrX905b9rMYjYSGsm4S46Ax7
         fLr0rhyxE7pzzzJKS2uO92ADgNGLCkWhwb9bzMc5WPlvPgMMAros9nZFMZK652Q6rrWT
         Ki8A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531eiDSD47QhPeV8+ZxjK4ix1qCsig9pky0km4HELnhzDNd8hEoy
	uCDBzUdh5JprtcA/JQ1M9oA=
X-Google-Smtp-Source: ABdhPJzkeeU2OacS5wMLKkJVb8OB9Okia58fbkyKavsYZkc63pw4YWUz4Z3DgnUqDpNkOmZBxTjg+g==
X-Received: by 2002:a2e:2a84:: with SMTP id q126mr6822221ljq.42.1591957373801;
        Fri, 12 Jun 2020 03:22:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:89d8:: with SMTP id c24ls1111555ljk.2.gmail; Fri, 12 Jun
 2020 03:22:53 -0700 (PDT)
X-Received: by 2002:a2e:96da:: with SMTP id d26mr6185484ljj.108.1591957373269;
        Fri, 12 Jun 2020 03:22:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591957373; cv=none;
        d=google.com; s=arc-20160816;
        b=eSsjAzhZZwRoFyJxSXpJla93zRFbogQo7cOQt1wCSpxrH3I6zXLNS6G/nvLyVog9FV
         1of4zWB6kgeLw7+vSHspDZjJGsdp8MwJ12OfufL4YdmZ5vtaiPAm+13fcu8nPn9D/pu3
         70Tj52WmpCblEFErhfNezaK81aVh4DZBb43Iwd1vnNvmllnxnoj3uNiYdn6dBOnzulFA
         klvooNkPM+eXdfhUB/2qwP6oIy0D3RWV4LQ/SHz3buFjBTj1LL7F7HmTz5+BtpyLWV0y
         wDzUzU8fcXfBjNOM9wB8jiBKy+4J0LWSrpH6ZoHDAHe9+RiV4+w2xBgXubqahKgaANRe
         CWOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=61bOAUewqye6991elOYNRVI8toOJ+FFe+wCFmgAigQ4=;
        b=NBNhsf4j+WIpl5IPtcBp4bdhj5FUbH3xqny29RGMfyPQKAjRpco7LNVgXmUEH+9pqt
         tQD1fPBRW42VLGLGzlYpqUoOlnG0ne4UoAPWBYLIWh3s+kNPq8fI9K55SJs8QLEj2BoR
         2OAw1dyIIdfsijtzB36uzASNBp49oeLRnRyxxRQXu40cjCw7e+0cCknWnmYX+7qEsVSr
         jv5+mJ1LDANdsvlDIOzyrVDoLm3mdTsJi7nfgQZtOvnvlXUl9jcon9jhT4bbP0fdW+7c
         nMDmXvIP4Zs5gYCGlF9s3f0yU2++kWdHoAI2ISilwujnvpT4uE0pIICsNhvJZ/XfMN6u
         CjiA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mliska@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=mliska@suse.cz
Received: from mx2.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id j14si282663lji.8.2020.06.12.03.22.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 12 Jun 2020 03:22:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of mliska@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx2.suse.de (Postfix) with ESMTP id 01CD0AE67;
	Fri, 12 Jun 2020 10:22:55 +0000 (UTC)
Subject: Re: [PATCH] tsan: Add param to disable func-entry-exit
 instrumentation
To: Marco Elver <elver@google.com>, gcc-patches@gcc.gnu.org, jakub@redhat.com
Cc: kasan-dev@googlegroups.com, dvyukov@google.com, bp@alien8.de
References: <20200612072159.187505-1-elver@google.com>
From: =?UTF-8?Q?Martin_Li=c5=a1ka?= <mliska@suse.cz>
Message-ID: <04575ef0-1fb4-ea27-adff-67dfe8d1c644@suse.cz>
Date: Fri, 12 Jun 2020 12:22:51 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.9.0
MIME-Version: 1.0
In-Reply-To: <20200612072159.187505-1-elver@google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Original-Sender: mliska@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mliska@suse.cz designates 195.135.220.15 as permitted
 sender) smtp.mailfrom=mliska@suse.cz
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

On 6/12/20 9:21 AM, Marco Elver wrote:
> Adds param tsan-instrument-func-entry-exit, which controls if
> __tsan_func_{entry,exit} calls should be emitted or not. The default
> behaviour is to emit the calls.

I support the patch.
What about Jakub?

Martin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/04575ef0-1fb4-ea27-adff-67dfe8d1c644%40suse.cz.

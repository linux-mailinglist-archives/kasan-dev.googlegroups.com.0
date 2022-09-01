Return-Path: <kasan-dev+bncBDY3NC743AGBBI74YSMAMGQEDZOP6ZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93b.google.com (mail-ua1-x93b.google.com [IPv6:2607:f8b0:4864:20::93b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A52C5AA3A2
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Sep 2022 01:20:04 +0200 (CEST)
Received: by mail-ua1-x93b.google.com with SMTP id k12-20020ab0538c000000b0039f64f6d1e2sf293762uaa.15
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 16:20:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662074403; cv=pass;
        d=google.com; s=arc-20160816;
        b=GX8DGWitDhRP10QXp6r0XMV5kX6AarkMwKjnTdQ5fLkjJxvwWJ6fVQU0HcbJgryyQO
         jgnYhrGzXhy7LjYvp3bVvM+3B3H4KzEqaY2fU/CsdoLCZtl5SsfpcFbJ7/zCZaj6RAy2
         XIb3dcVwZHJAyk6EsUVopYbEY0TMuam/B36lYvubqsOcU6ZwFv0/sSUX9QxFD/PS3tGx
         MlLotbl/8xQr/6VfgI72NjvgWu5BQxij+anglssf9+JjO2m18L5JDdyvc3JgQB9gnPPi
         xLrPJtsGse4YEAzsyYGK9WCVoo8lxCGsdse9RiMFBYPQXC07vtxZuyCt8IPXYh1D18N8
         7vvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=waR97WBzr6HOZzaFfGpxWin+yR9HXn1J8aq8y9IxZfQ=;
        b=BOKZZt0veoQh0mYlmVghdH4O1vbAZVBKg2oiXOqSMSvWG1AZctJ1OWvcScHi2kOH7E
         1tp/t5rIEuvxTm0JyidKgr70CYB8J8gdQHk44SEQ+p4ZP7NNd3EqrBuv+E3i4AJcJl2H
         WXd8qgjhm690j7CJg/sGUYUzVYzQ30xpTEpYJo0WE/MQzfIF8ObprRgH9KvXXq/FnslO
         UgIBWF85jZk/JCeX+3HibIuiblFWpaAFZCxLP22bW0utxOoKi9hnOPubh0W/P/u1oCQz
         zH2kej+N2tf2RPQKS7RbnDYYnyLt0HlZhDmTo3sxISyb04qbm90xcfC+YqTbV/q5jlzq
         LDiw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 216.40.44.16 is neither permitted nor denied by best guess record for domain of joe@perches.com) smtp.mailfrom=joe@perches.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:from:to:cc:subject:date;
        bh=waR97WBzr6HOZzaFfGpxWin+yR9HXn1J8aq8y9IxZfQ=;
        b=tI9RB6rNHwZN4tHvc6pGY03XITU91Cko/cbntBG33zVokcMZRakfAy5vTbNEH2tog6
         ArdxIv0ZWcAH4uKnDFO6lOhBEP3g6GCivLdnQDFlvwn0kdNLQj6t9tLxuNUvJltz+TPO
         sYqbR+/rmrsFrsQV9v9A2AUrZSeJAwfGhXlDlT/wUIRCbN0ICzB0XFgJvXn3QWjkzn+M
         FMyLFR3WA4UaTKELklQxEvt7VI+dzi2WcDQ5SEQtx2SWTRtx6eTO631qHGhJKhjQsfx+
         bRyKbuyl/pWU3jKnT1gDqBjD0epZvdg1z+gENm5UvAnXTLBQOm3a+uR9p0FBYMLpU86R
         xm3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:date:cc:to:from:subject
         :message-id:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=waR97WBzr6HOZzaFfGpxWin+yR9HXn1J8aq8y9IxZfQ=;
        b=Qn2zGggYlbMwZKkMm1QbijM60m0R+RyRBSx7wdYWeozhOBmI8+AYX5lgL4FNdMhoNI
         QbDnrcZJ+B1DaeNvJwsF+FVpycL9YYPGYe1+G97R5YVIK8+98vb/eFUzRoN372shSuso
         y3CHVjkNW5dkoYu3b9G25VZ0Q3IdSHkHj/06HLBBhJ8Q0rcP5G4uo5RjQ+d/tmrKBvqT
         ShU4/RWrn3hi1ZauE9RVZyRUHNaGSAPPV8paDL4DNLlHmlGx4SXmeEGkK58ndc1HQHEM
         rvr/ZEm3YgSqIxKPYLrMlaL49E7Xda4gCtASGBr6IG0+HzlaEbf1RO3ZNXnOby+7BiuA
         YMZA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2lEbcz+u2xQMlbFVjRkEM02q4SB1vW5msdQabn9boMlk7qcyVr
	7c1AAeRBOzRRCn/FcZgfYtw=
X-Google-Smtp-Source: AA6agR62v97ZEVxKTXb+piquRY2equkqFgUrRg5WiLWpfIFIz8w7dWSYfGOaH1PhfqFHZA3n0L0a9Q==
X-Received: by 2002:a67:b249:0:b0:390:7faa:e7f1 with SMTP id s9-20020a67b249000000b003907faae7f1mr10486627vsh.83.1662074403298;
        Thu, 01 Sep 2022 16:20:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6130:6ca:b0:392:a2c0:f88c with SMTP id
 bl10-20020a05613006ca00b00392a2c0f88cls209257uab.5.-pod-prod-gmail; Thu, 01
 Sep 2022 16:20:02 -0700 (PDT)
X-Received: by 2002:ab0:7382:0:b0:3a2:5ce:768f with SMTP id l2-20020ab07382000000b003a205ce768fmr5400429uap.84.1662074402658;
        Thu, 01 Sep 2022 16:20:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662074402; cv=none;
        d=google.com; s=arc-20160816;
        b=IFk6H6fpKTtJjlMMcaca0yDwaAfOytuwrfTSJ2unzQZiYMUdScrwB7URrKDpyt2dXV
         saGZb4xYH7AoDg2llpuxD//204Vju1dUPP4WDIpXnxWR+4Kq+DMX5PpXI2dQQT7rkOZG
         lDo3pwdoxmkbx2Tsd2m955uX6U4NkT3dyJeZQgrPR7CRd1P7e+wj1oZPCJ/k/4Mr+Z65
         MBmVbWXWMm++NFw+hjc61QsH8zXohuwWIQqj8omcfmaeicFULiGLASAKerl7SW3p65z7
         fte/gWbpBBKWHUZ21GzO42cgJaPpGN0yZj5UWSYjt7zLIEKDvyxeaozQ2ltv1TdWUkhM
         eOcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id;
        bh=KHhjVPvWWy6GCJ08QhtRbuOecr40l67u4XmpG3GXwT4=;
        b=MlOeQaXMDaiED6nZs43chkKR1O8sHFU9Xf0Jbucoh7lv4nrMuTGPEasZInLdapRODL
         YF1ypzNj+L9wwzhXrK34W7zXDhoasVDa0fsNGsXCBPcJX5VAV+wH4PXm2um01jSXWVEe
         bj7vk+SfwBKoZkykPcZfBv91N8OAc++pQWDjNUMD02OslqveTZRkhk7fkBLynTq7GlHk
         Onst4KDo5UQbX8cTkanUGXMLe8gAtm66biixPRdPTmYcUJN0s0hlC7gjUpe0PAbx4q68
         s0A5+WBUGDC6+lizDYnkvUegYM9yki15A8lCRJdsmxGbDyuCNzxBrmIAqVAHKfhYCzvl
         IQsg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 216.40.44.16 is neither permitted nor denied by best guess record for domain of joe@perches.com) smtp.mailfrom=joe@perches.com
Received: from relay.hostedemail.com (smtprelay0016.hostedemail.com. [216.40.44.16])
        by gmr-mx.google.com with ESMTPS id q199-20020a1f2ad0000000b0037d0dfd4d08si18370vkq.0.2022.09.01.16.20.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Sep 2022 16:20:02 -0700 (PDT)
Received-SPF: neutral (google.com: 216.40.44.16 is neither permitted nor denied by best guess record for domain of joe@perches.com) client-ip=216.40.44.16;
Received: from omf02.hostedemail.com (a10.router.float.18 [10.200.18.1])
	by unirelay01.hostedemail.com (Postfix) with ESMTP id 1E25A1C6992;
	Thu,  1 Sep 2022 23:19:58 +0000 (UTC)
Received: from [HIDDEN] (Authenticated sender: joe@perches.com) by omf02.hostedemail.com (Postfix) with ESMTPA id A9ECF8000E;
	Thu,  1 Sep 2022 23:19:36 +0000 (UTC)
Message-ID: <c3a6e2d86724efd3ac4b94ca1975e23ddb26cc6f.camel@perches.com>
Subject: Re: [RFC PATCH 28/30] Improved symbolic error names
From: Joe Perches <joe@perches.com>
To: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
 hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de,
 dave@stgolabs.net,  willy@infradead.org, liam.howlett@oracle.com,
 void@manifault.com,  peterz@infradead.org, juri.lelli@redhat.com,
 ldufour@linux.ibm.com,  peterx@redhat.com, david@redhat.com,
 axboe@kernel.dk, mcgrof@kernel.org,  masahiroy@kernel.org,
 nathan@kernel.org, changbin.du@intel.com, ytcoode@gmail.com, 
 vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
 bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
 penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
 glider@google.com,  elver@google.com, dvyukov@google.com,
 shakeelb@google.com,  songmuchun@bytedance.com, arnd@arndb.de,
 jbaron@akamai.com, rientjes@google.com,  minchan@google.com,
 kaleshsingh@google.com, kernel-team@android.com,  linux-mm@kvack.org,
 iommu@lists.linux.dev, kasan-dev@googlegroups.com, 
 io-uring@vger.kernel.org, linux-arch@vger.kernel.org, 
 xen-devel@lists.xenproject.org, linux-bcache@vger.kernel.org, 
 linux-modules@vger.kernel.org, linux-kernel@vger.kernel.org
Date: Thu, 01 Sep 2022 16:19:35 -0700
In-Reply-To: <20220830214919.53220-29-surenb@google.com>
References: <20220830214919.53220-1-surenb@google.com>
	 <20220830214919.53220-29-surenb@google.com>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.44.4 (3.44.4-1.fc36)
MIME-Version: 1.0
X-Rspamd-Server: rspamout03
X-Rspamd-Queue-Id: A9ECF8000E
X-Spam-Status: No, score=0.64
X-Stat-Signature: iwqjhu65bfnp7s38he58qcgfcrx3mruu
X-Session-Marker: 6A6F6540706572636865732E636F6D
X-Session-ID: U2FsdGVkX18FfjZ7BuRv/DHsUMYX6e6vN/rFvSwIdRQ=
X-HE-Tag: 1662074376-819350
X-Original-Sender: joe@perches.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 216.40.44.16 is neither permitted nor denied by best guess
 record for domain of joe@perches.com) smtp.mailfrom=joe@perches.com
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

On Tue, 2022-08-30 at 14:49 -0700, Suren Baghdasaryan wrote:
> From: Kent Overstreet <kent.overstreet@linux.dev>
> 
> This patch adds per-error-site error codes, with error strings that
> include their file and line number.
> 
> To use, change code that returns an error, e.g.
>     return -ENOMEM;
> to
>     return -ERR(ENOMEM);
> 
> Then, errname() will return a string that includes the file and line
> number of the ERR() call, for example
>     printk("Got error %s!\n", errname(err));
> will result in
>     Got error ENOMEM at foo.c:1234

Why? Something wrong with just using %pe ?

	printk("Got error %pe at %s:%d!\n", ERR_PTR(err), __FILE__, __LINE__);

Likely __FILE__ and __LINE__ aren't particularly useful.

And using ERR would add rather a lot of bloat as each codetag_error_code
struct would be unique.

+#define ERR(_err)							\
+({									\
+	static struct codetag_error_code				\
+	__used								\
+	__section("error_code_tags")					\
+	__aligned(8) e = {						\
+		.str	= #_err " at " __FILE__ ":" __stringify(__LINE__),\
+		.err	= _err,						\
+	};								\
+									\
+	e.err;								\
+})

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c3a6e2d86724efd3ac4b94ca1975e23ddb26cc6f.camel%40perches.com.

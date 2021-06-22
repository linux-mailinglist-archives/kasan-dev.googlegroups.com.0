Return-Path: <kasan-dev+bncBCII7JXRXUGBBK5UZCDAMGQEOALUR5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 030913B0B36
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Jun 2021 19:13:16 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id q15-20020adfc50f0000b0290111f48b865csf10004476wrf.4
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Jun 2021 10:13:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624381995; cv=pass;
        d=google.com; s=arc-20160816;
        b=InH6+kvPA6lM64Po7vuTApmpk0scuRkWixRfEqj+fszd1kPOYr4JQg6JsiYji13AKJ
         fqSxGqoM7CB1KiMjeglfSIJOcjdP8716CWykqYt5Sf80hl2F5m6klcTP16mFuK6XVv5w
         gQsUd6lIHxW97KhB6MkjKM3wPrRfqanXtHq3/jtwx24z8YkGKs9STNfIQnhWa4h3hTwg
         YfoSrYIQTNbHUCIZyw5VODKjIV5HAvT2bpE9FHcd16hty11XbRqt/IG/790l3Oi9jIem
         Wi+GCfIM5NY7h3XdPwJzw5taBKdTdlE4+itdQY7ULPRIAwT9ymeFkmfDmh0wht80XNpx
         ur5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=tnirgY1Na9RVITmLvpnVwT1MSPu0vAw4OEH6eKQnvPM=;
        b=HNtIAZil12bJuRSp1Y1Ecx0ArYkUl7ebJCdksZoUoMHFPBfx/JFIJQZU2VRKqDDgkP
         bKZMYaYnSk/bGqHFpAn8duCVgSyVj45F71FJFF6CBkIYGqwW3Dk94Om0CheLA5nSam8z
         4oDlSLzueH6SDs4OQC7jstGkuMq3Yr8wqS/Y0dIfP4CwRSBi/BzKgnLU/twuHZKjNyeC
         Iu91TTFzJ5caGph2e7+VBFCpaKzQDhZfFBbHUXOB2iVL7Rv2LbFkuLo6oUIlQcjKhz1s
         G83uxqMQyg+xSaMC9NYPHJ8s/S1VkJasQNrk/2MqUwWWLIOyY7d5YofnjFfAp2b32tj/
         8qrw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@codewreck.org header.s=2 header.b=pPD0vIhj;
       dkim=pass header.i=@codewreck.org header.s=2 header.b=pPD0vIhj;
       spf=pass (google.com: domain of asmadeus@codewreck.org designates 91.121.71.147 as permitted sender) smtp.mailfrom=asmadeus@codewreck.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=codewreck.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=tnirgY1Na9RVITmLvpnVwT1MSPu0vAw4OEH6eKQnvPM=;
        b=evAJCo0RVfEdEYshiy9AC0c/HBMRgrMF9mhzlCa8xTgsS9O1Bh8hODShPDvZUvSAA3
         fQV1Ba/R7K27/cyIwAUJxsy/00FnQAPdfdlQHcwOh/bhAuadIbtutaFnRRivXxPnIJ8w
         rI4Vg5Q22vWUh7dmOZozM2CgHB6ZgjC9oxCTFsffQihJvxaT1VGJaD1pKU/cWmSVV+kE
         DPgxFFimor5cP/Uv0kKidT3KFPmhgN+pTy7hNtDE6O0KQnsltAeN0fATmea5M5fu4KGl
         yIZWxA1D4bPA/Ey+PQ8OykEz1H1fAmmxCiUYn8+mU13ZJ2mYaH3dbYyGgtZNJFsr6YTu
         GmNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=tnirgY1Na9RVITmLvpnVwT1MSPu0vAw4OEH6eKQnvPM=;
        b=Ua3tnKzwN0k2fkjtaa6KSosEplGbLvWeQFos0cNH+zDJERFRed5wRRJnE4d2jpssKD
         Mn0AGIEVag8bAxprvkQWU2mA7zT7B3w18Ho9QqNcvx78OjahaGrmmfgkcmN0vcNW1p69
         /JUlU8OOlQ70onz+x70LuF/DnTta3YOxnwM0zU/r/JoRhpGBkZZNMiUuFSqxyxc85P8S
         nWSCcRgB46rdm6wuQmtzBY+SRLOA8ZdY9/jkL75BRwiC8d80KbuKkVHjdVYO3ON/Db23
         g4cxaffpPMh5kN+y2azM9raI7fRou2u2ohocQ+5oXOYypZy9upcczptBOtVaCaYvK3iT
         /25g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531slFRH2Do4qKtN+7qI3jFbvdQBVjwO1Brqqa3nr3ViVx9O/OE7
	9gJY4lMDQ4Kni2ZSWC1AW08=
X-Google-Smtp-Source: ABdhPJwOd48AKlnXZ+9NAQXIMwnNBaO3AEzHA61w2xa4sgkg48g74M3vYoLKRKgmC245jtDsbaGxBQ==
X-Received: by 2002:a1c:7212:: with SMTP id n18mr5524449wmc.58.1624381995700;
        Tue, 22 Jun 2021 10:13:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:45c9:: with SMTP id b9ls593612wrs.1.gmail; Tue, 22 Jun
 2021 10:13:14 -0700 (PDT)
X-Received: by 2002:a5d:5988:: with SMTP id n8mr6137522wri.261.1624381994862;
        Tue, 22 Jun 2021 10:13:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624381994; cv=none;
        d=google.com; s=arc-20160816;
        b=L2jnYiskOrqzU9jQQu5zNaGzfQcGEE1sklNCowRcTd45yUWkhg/5/CpeuAJY3ZJ19d
         M6ew07YW225eb/vqo0xPgY7YCzWF+BwgH8rRVojL0yORt5FOnzWNAZOVqWwfZM4/NaP1
         +l0CWzKWPLR7QBwDujaJKGu0UkHiXSpEwwG3FmF3+mn4TNhYWhdwRc/f40iByusYMSDK
         Pp+4CDyhh/AF/9G2qTVWVgMc1SMyqjt6uAn5copCmsBvnp9DDNrbz8gLkyJ0SjtLLDmP
         SvPceNxfd4f/Zvwpw51JMTe4GMT5NR7bDXnAi6iXOnJl6uqOdczyp1woWlOec+30ydFM
         k4vA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=tdLraN26AJmikOf9cCVnkJCdq/46SM04tSpwRtDPI0E=;
        b=dM5cLP/qnrfVp+XVAHU5cXA67rrwh8SFgrY10PRqTxP41kfy77FUFuWVkGWjsYBPbC
         m6UU8JT8LR0NsJb19wOXYokyt9m9nd3hxU7BZLGvfNvUEMaytN9zn6/d60A5XejTQyNK
         4XDB7m3pV6N7Pzbxh8zp9+YrXAIR2caU9ZLBKWL+XBHQ3l4twGjpeK+n+b4/cpaIjNVK
         c+3d4D9/eWXZfWHOBmOJMCecmCphFSxFvQWVA+3dLStfiYUUCS/b/GkH+eNZi2eEMjbC
         wYOL1mGlnx1Cyj0/j4dOZ96oqk8vy97L0U5E1bPI78w2U+SupBhDC8P/0rMW5M4s7qgx
         03UQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@codewreck.org header.s=2 header.b=pPD0vIhj;
       dkim=pass header.i=@codewreck.org header.s=2 header.b=pPD0vIhj;
       spf=pass (google.com: domain of asmadeus@codewreck.org designates 91.121.71.147 as permitted sender) smtp.mailfrom=asmadeus@codewreck.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=codewreck.org
Received: from nautica.notk.org (nautica.notk.org. [91.121.71.147])
        by gmr-mx.google.com with ESMTPS id z70si151742wmc.0.2021.06.22.10.13.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 22 Jun 2021 10:13:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of asmadeus@codewreck.org designates 91.121.71.147 as permitted sender) client-ip=91.121.71.147;
Received: by nautica.notk.org (Postfix, from userid 108)
	id 63DDCC01A; Tue, 22 Jun 2021 19:13:13 +0200 (CEST)
X-Spam-Checker-Version: SpamAssassin 3.3.2 (2011-06-06) on nautica.notk.org
X-Spam-Level: 
X-Spam-Status: No, score=0.0 required=5.0 tests=UNPARSEABLE_RELAY
	autolearn=unavailable version=3.3.2
Received: from odin.codewreck.org (localhost [127.0.0.1])
	by nautica.notk.org (Postfix) with ESMTPS id B4B08C009;
	Tue, 22 Jun 2021 19:13:11 +0200 (CEST)
Received: from localhost (odin.codewreck.org [local])
	by odin.codewreck.org (OpenSMTPD) with ESMTPA id 5de002b9;
	Tue, 22 Jun 2021 17:13:09 +0000 (UTC)
Date: Wed, 23 Jun 2021 02:12:54 +0900
From: Dominique Martinet <asmadeus@codewreck.org>
To: jim.cromie@gmail.com
Cc: kasan-dev@googlegroups.com, v9fs-developer@lists.sourceforge.net,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [V9fs-developer] KCSAN BUG report on p9_client_cb / p9_client_rpc
Message-ID: <YNIaFnfnZPGVd1t3@codewreck.org>
References: <CAJfuBxxH9KVgJ7k0P5LX3fTSa4Pumcmu2NMC4P=TrGDVXE2ktQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="6SucSdJFMdQFulNL"
Content-Disposition: inline
In-Reply-To: <CAJfuBxxH9KVgJ7k0P5LX3fTSa4Pumcmu2NMC4P=TrGDVXE2ktQ@mail.gmail.com>
X-Original-Sender: asmadeus@codewreck.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@codewreck.org header.s=2 header.b=pPD0vIhj;       dkim=pass
 header.i=@codewreck.org header.s=2 header.b=pPD0vIhj;       spf=pass
 (google.com: domain of asmadeus@codewreck.org designates 91.121.71.147 as
 permitted sender) smtp.mailfrom=asmadeus@codewreck.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=codewreck.org
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


--6SucSdJFMdQFulNL
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

jim.cromie@gmail.com wrote on Tue, Jun 22, 2021 at 10:42:58AM -0600:
> I got this on rc7 + my hacks ( not near p9 )
> ISTM someone here will know what it means.
> If theres anything else i can do to help,
> (configs, drop my patches and retry)
>  please let me know

Thanks for the report!

> [   14.904783] ==================================================================
> [   14.905848] BUG: KCSAN: data-race in p9_client_cb / p9_client_rpc

hm, this code hasn't changed in ages (unless someone merged code behind
my back :D)

I had assumed the p9_req_put() in p9_client_cb would protect the tag,
but that doesn't appear to be true -- could you try this patch if this
is reproductible to you?

The tag is actually reclaimed in the woken up p9_client_rpc thread so
that would be a good match (reset in the other thread vs. read here),
caching the value is good enough but that is definitely not obvious...

-- 
Dominique

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YNIaFnfnZPGVd1t3%40codewreck.org.

--6SucSdJFMdQFulNL
Content-Type: text/plain; charset=utf-8
Content-Disposition: attachment;
	filename="0001-9p-net-cache-tag-in-p9_client_cb.patch"

From 1135d60baa5d743e8a123812428a342b101e290e Mon Sep 17 00:00:00 2001
From: Dominique Martinet <asmadeus@codewreck.org>
Date: Wed, 23 Jun 2021 02:12:20 +0900
Subject: [PATCH] 9p net: cache tag in p9_client_cb

req->tc.tag is not safe to access after status has been set,
because tag is reclaimed by p9_client_rpc and not by the p9_req_put
below as one might think.

Reported-by: jim.cromie@gmail.com
Signed-off-by: Dominique Martinet <asmadeus@codewreck.org>
---
 net/9p/client.c | 6 ++++--
 1 file changed, 4 insertions(+), 2 deletions(-)

diff --git a/net/9p/client.c b/net/9p/client.c
index b7b958f61faf..3e95a56ead80 100644
--- a/net/9p/client.c
+++ b/net/9p/client.c
@@ -419,7 +419,8 @@ static void p9_tag_cleanup(struct p9_client *c)
  */
 void p9_client_cb(struct p9_client *c, struct p9_req_t *req, int status)
 {
-	p9_debug(P9_DEBUG_MUX, " tag %d\n", req->tc.tag);
+	u16 tag = req->tc.tag;
+	p9_debug(P9_DEBUG_MUX, " tag %d\n", tag);
 
 	/*
 	 * This barrier is needed to make sure any change made to req before
@@ -429,7 +430,8 @@ void p9_client_cb(struct p9_client *c, struct p9_req_t *req, int status)
 	req->status = status;
 
 	wake_up(&req->wq);
-	p9_debug(P9_DEBUG_MUX, "wakeup: %d\n", req->tc.tag);
+	/* req->tc.tag is not safe to access after status has been set */
+	p9_debug(P9_DEBUG_MUX, "wakeup: %d\n", tag);
 	p9_req_put(req);
 }
 EXPORT_SYMBOL(p9_client_cb);
-- 
2.31.1


--6SucSdJFMdQFulNL--

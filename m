Return-Path: <kasan-dev+bncBAABB2XG27YAKGQE7TLH5GI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 12EF11345FF
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Jan 2020 16:21:15 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id c2sf1909995edx.19
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Jan 2020 07:21:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578496874; cv=pass;
        d=google.com; s=arc-20160816;
        b=WLYWmFngtFax6hEJwF6BBmspRa/+0HqthC/jj+5SX+tG+RLMmqvXO12jDuHcL+MkWI
         w3QexFDxbMHQ6JB+BxT9EUJo2hgbvKp0VMxNTKcGNhEyO2G3inM3BcYaAixlVuvZ+t2Q
         8irKa58RbpZD/Ab/Ya6R4Ij8YZxmdO8+eEZm7YgpJ6ZRJIvvrftwl3GgJB2uRW0DaHVb
         xHqEEmj3tjd32b0fNOo/NqGGQWjkq6eOhLHSPPtMphtyo/YpWTw+hNbr5RBZUwwMhJuZ
         wt96k4c0oQfZDxKsms4S29D/IrNFy95PTlbEnocL2COOGTCsTyCSh6PqupjvYTqgI6Vk
         yH7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:ironport-sdr:sender
         :dkim-signature;
        bh=aToBqKgSq2sQmWLadlskR4BTPwIJ6zK8ualmIAbehBA=;
        b=xHEpWnOtonG8bp0vRtm7g78tgSsnGhJ3l08zXUSJIGKBqhNlEExib55KebodxGfYw6
         MaLF0203RaKKaqWIGlj2Z8gj73P1V5ZzKALfuPoCiS95gtblDatzzMBTIxreo4QPkQKd
         5BEXr+KhKEL6ZcXCN/Z1+BNymUQ/bDLcfjWN8Qqd6nPWVvk2Dboi1D9zFH2GBn9fMOvw
         uiriqYxsLGzr73CLUfv4LcTspQxPmYrRHPGLDD0m2H/alG5OLi5GaIfyg9pKytNFzbL2
         PYlLzAgFNpU1Sk9PSIvxp2ydCb2gTK6kOjMZyssgrHesPTwWSVC3kK5reydGLLAjZ0qo
         5VuQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=D8IejQT0;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.168 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:ironport-sdr:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=aToBqKgSq2sQmWLadlskR4BTPwIJ6zK8ualmIAbehBA=;
        b=QJj82t22tJ3H7sD3GKV40+No8JJKzkr38W3YcCFujFlgTSWBzfcWE1qx4TpS4yxYVB
         hoi4ggnWctyZI4vYnt85MPuMrXQA2+FuUCuZNqGRn1R6cQKEEsirni7DnCR9hHWP7AH5
         HtYDmqYkGvaWS61WBg02eNmmh4oK6v+hpl5zsc05t2MqOgRWsifbWgu8gMLxhjxzTrdn
         LJH0kxym2X8uQUytinlmBFhZiNOSfCM+L1Jd2+OjxnPoEJNOBb3idJz42gHgAQ8UeXeb
         2GY1teUmF6qpJjA9x05GuEtHIhNqqNELwJr4CfqimCSaJUh5dvE3u2eI5On9HYeV35Vh
         EUHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:ironport-sdr:from:to:cc:subject:date
         :message-id:in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aToBqKgSq2sQmWLadlskR4BTPwIJ6zK8ualmIAbehBA=;
        b=QY619xs8mLvx/p2SsbStXgEMhCxFy5WtNTC7dgwZcILjVXUGBcLhuYNVOP97fEs35Z
         U7F+kiBlBpnfSmGGPkb1b87EnJEX6LKNlYQ/J5SHFHhknSHlX13tGsH7A+kcEKjAGuw4
         JT6wO3nMMC7IDgljAM3fh3r2fyqiKCGToI4ziZ4+8/lDyCs/ICiHJwko1f9U6RKYRFPz
         IixnpLbS7AkVyG18ZKlKzmEOev2UGWftNFSTnbReyzJBE5+UF/mo2eaJYKs4RhWdCMz4
         c7gZp33F6JmcYnJ6ASIjcKbEo/R/YtxTn9FIH/A4EVIJm0+H0CE0JkGle7BBq9X2v+T2
         p/4A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVNrDn5Pc537kQ9UsazmTqn41ZSLMjswVnRlcBlJJMWGGCjlsFp
	CsafwmrZyxmIDz2KWVe8Xoo=
X-Google-Smtp-Source: APXvYqw0JdvZwXzaqvuGgwipsdku7rRt8PFc3sx5H7Xri4ztzD+FEA7JMe60i83Lt9UolXWnff7Weg==
X-Received: by 2002:a50:fc85:: with SMTP id f5mr6074873edq.294.1578496874752;
        Wed, 08 Jan 2020 07:21:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:cd1b:: with SMTP id oz27ls792595ejb.4.gmail; Wed, 08
 Jan 2020 07:21:14 -0800 (PST)
X-Received: by 2002:a17:906:3596:: with SMTP id o22mr5365714ejb.235.1578496874407;
        Wed, 08 Jan 2020 07:21:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578496874; cv=none;
        d=google.com; s=arc-20160816;
        b=tOaBV0bGSkeEE15+FQgzdjfocwuseO44J3weutkSR476IUrZsG/bBn/Ntpy7E8pY8+
         9+yGOr/a8TfKqsQUr5s4J4EofznXUaz+AvsPp+M/KXJcdEMYtIzbSYN+Pjuupfc5p+jF
         fTRUWt3/azSh7fvNcBkA0hX4gQLYsca8vycyPqVRNKjiGOzsLl0ay3eCI3Q5c32/3hx9
         PP5N7h970mk8DTVEx54dRHOfSorUsAjhq4cy1D/PkFsNCl8DIfi3FJgMjq05RjIx4XLM
         KvZ4jRsgkffzY6diyblbZXf3v2in4i8/0v1ZG1w9ufQqLs7KnKVLrJfmGQJwY4Hoo7pw
         TjBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:ironport-sdr:dkim-signature;
        bh=gjr4z5rTQ0qKOi5upkygLoW8ZPyIwW0ZAXXqVImOvAc=;
        b=pjwdj82PmH0zw2MdEDRlYpkzVEh2LPJxTSjpt7BRXuhVF3kwAodBP8f/qxwW9dGH6m
         /p0z/0IW8zdAIXw/M0/Wy9HEs22a+w0Wre+C573ahYtshJH/oexbM2O3buwWVtIceLtH
         7oJPVW+sdTw+QxyK7KAfWDyGcWRMSwuQdmURu2guQTbJL58W24Na2cf1DJ3vLRHWLPlC
         c7i/V7Gqj8oxLFjAc7ZQZECDLVqoMBznfZs7NNcr3Q0l+s6Od/jPp29cS6ybykQogglC
         KiA8LGOLYqG88HbLBjXn+F7qAgG3Z/nT7ibLQYckkD7yGqQWWFbVZUxsg3izR8HW/MLu
         +HMQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=D8IejQT0;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.168 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
Received: from esa5.hc3370-68.iphmx.com (esa5.hc3370-68.iphmx.com. [216.71.155.168])
        by gmr-mx.google.com with ESMTPS id ba12si148870edb.3.2020.01.08.07.21.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 08 Jan 2020 07:21:14 -0800 (PST)
Received-SPF: pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.168 as permitted sender) client-ip=216.71.155.168;
Received-SPF: None (esa5.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  sergey.dyasli@citrix.com) identity=pra;
  client-ip=162.221.158.21; receiver=esa5.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible
Received-SPF: Pass (esa5.hc3370-68.iphmx.com: domain of
  sergey.dyasli@citrix.com designates 162.221.158.21 as
  permitted sender) identity=mailfrom;
  client-ip=162.221.158.21; receiver=esa5.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible; x-record-type="v=spf1";
  x-record-text="v=spf1 ip4:209.167.231.154 ip4:178.63.86.133
  ip4:195.66.111.40/30 ip4:85.115.9.32/28 ip4:199.102.83.4
  ip4:192.28.146.160 ip4:192.28.146.107 ip4:216.52.6.88
  ip4:216.52.6.188 ip4:162.221.158.21 ip4:162.221.156.83
  ip4:168.245.78.127 ~all"
Received-SPF: None (esa5.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  postmaster@mail.citrix.com) identity=helo;
  client-ip=162.221.158.21; receiver=esa5.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="postmaster@mail.citrix.com";
  x-conformance=sidf_compatible
IronPort-SDR: TqQkzmi9JuPNn7Gy/JzerQopbW+J7Eg/HSvyodqgKwy6liyt49GclLM2WQADT6NXTl/kZ1p9du
 CB4UFLD6ASxEzL/NopyZoPRTvUJtMdivzl3aoQZxabTiYizCWjwv79t8XuBMkzX7EwggzZ5f7f
 akop21WbU3fEBVEfVMqKZd4pJlcm3cFSfFwHD9lr0HEnFYtOObpdUw54kRdENEoSPEmA10/AUG
 I/1BaEq0Xz7pvyfyQ5KUeoqXtJZyfi9TrJLmDoPbTN07bw6Li+uwoY0bWydcCWLSGwnyQoo4SG
 iuU=
X-SBRS: 2.7
X-MesageID: 11004133
X-Ironport-Server: esa5.hc3370-68.iphmx.com
X-Remote-IP: 162.221.158.21
X-Policy: $RELAYED
X-IronPort-AV: E=Sophos;i="5.69,410,1571716800"; 
   d="scan'208";a="11004133"
From: Sergey Dyasli <sergey.dyasli@citrix.com>
To: <xen-devel@lists.xen.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Boris Ostrovsky
	<boris.ostrovsky@oracle.com>, Juergen Gross <jgross@suse.com>, "Stefano
 Stabellini" <sstabellini@kernel.org>, George Dunlap
	<george.dunlap@citrix.com>, Ross Lagerwall <ross.lagerwall@citrix.com>,
	Andrew Morton <akpm@linux-foundation.org>, Sergey Dyasli
	<sergey.dyasli@citrix.com>
Subject: [PATCH v1 3/4] xen: teach KASAN about grant tables
Date: Wed, 8 Jan 2020 15:20:59 +0000
Message-ID: <20200108152100.7630-4-sergey.dyasli@citrix.com>
X-Mailer: git-send-email 2.17.1
In-Reply-To: <20200108152100.7630-1-sergey.dyasli@citrix.com>
References: <20200108152100.7630-1-sergey.dyasli@citrix.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: sergey.dyasli@citrix.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@citrix.com header.s=securemail header.b=D8IejQT0;       spf=pass
 (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.168 as
 permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=citrix.com
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

From: Ross Lagerwall <ross.lagerwall@citrix.com>

Otherwise it produces lots of false positives when a guest starts using
PV I/O devices.

Signed-off-by: Ross Lagerwall <ross.lagerwall@citrix.com>
Signed-off-by: Sergey Dyasli <sergey.dyasli@citrix.com>
---
RFC --> v1:
- Slightly clarified the commit message
---
 drivers/xen/grant-table.c | 5 ++++-
 1 file changed, 4 insertions(+), 1 deletion(-)

diff --git a/drivers/xen/grant-table.c b/drivers/xen/grant-table.c
index 7b36b51cdb9f..ce95f7232de6 100644
--- a/drivers/xen/grant-table.c
+++ b/drivers/xen/grant-table.c
@@ -1048,6 +1048,7 @@ int gnttab_map_refs(struct gnttab_map_grant_ref *map_ops,
 			foreign = xen_page_foreign(pages[i]);
 			foreign->domid = map_ops[i].dom;
 			foreign->gref = map_ops[i].ref;
+			kasan_alloc_pages(pages[i], 0);
 			break;
 		}
 
@@ -1084,8 +1085,10 @@ int gnttab_unmap_refs(struct gnttab_unmap_grant_ref *unmap_ops,
 	if (ret)
 		return ret;
 
-	for (i = 0; i < count; i++)
+	for (i = 0; i < count; i++) {
 		ClearPageForeign(pages[i]);
+		kasan_free_pages(pages[i], 0);
+	}
 
 	return clear_foreign_p2m_mapping(unmap_ops, kunmap_ops, pages, count);
 }
-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200108152100.7630-4-sergey.dyasli%40citrix.com.

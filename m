Return-Path: <kasan-dev+bncBAABBNHH6XYQKGQEDNATWLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id B124C155949
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Feb 2020 15:27:00 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id cq10sf2006954edb.5
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Feb 2020 06:27:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581085620; cv=pass;
        d=google.com; s=arc-20160816;
        b=uq3+hSsPUvcDLY/XaSGiudasS+t3U73cnxywH4hPdLszSHxers/bNQu/1T6Y3t6TIl
         dfyLVdahnXXwyQodEY7qKYJcwKinpvopfHu8Ag8vIagorHo0MeDMhWcW/wK01X4jkEcX
         9wO4OoIBppS73dkT+Mmxf+yDPh7wzZcmKFmlfs5HshAN51gT8jU0tUPplbA95ek8I6TF
         jDDguLoFJzqDeMNnWjJ8sb2XPSmyJMB7sjaQpgSM6NrxAw1GraLppmzc2CAjY0lZ66t1
         zJ1vkfGbFNzt/WuY0wMQ8JZ6qnFrbW11vL5U8FkoQGzml6Lr8zvq2A+mh5dtj8xohZ1B
         pIzw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:ironport-sdr:sender
         :dkim-signature;
        bh=J+SwsVkIkXUHNBlwfbaRh6phQ9aQ7CdxMqodpIXtLDU=;
        b=DerTd0+aUXMmcsV7SsWShImsUn/1aKh6orcJ2Vr3tMkULy0BZ282dwwIMg83+HRgAO
         XbzhdqFj80/W7u/O1X8qA+qZTBjTYePt+oqgqetNqQgHAgbnHqP/M0+PjwohF7moXgsl
         VbF3s6ZqiBJZ7u/Xk/Zm9PfS7/a6v6KrjlSGeu20EKWRYd8zFsvr32cY/aIv01bzmKux
         Qb5ZKRZNJ1oXgeNGGh7WqyzMXyxvPOSEJac1nfTrec57gUYeCYdPBaPPSg8KMAqDtOqw
         mrmvxyVEghxW4QtWQBRxKu9ai5Pn9G42YiHthvvu0IwIhex/sGSWt0ZizaAOCZzejgiu
         qkzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=MjT9lM4Z;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.168 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:ironport-sdr:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=J+SwsVkIkXUHNBlwfbaRh6phQ9aQ7CdxMqodpIXtLDU=;
        b=MAzVlFRwfyxbpAUlOo8/zwRTHCheA7cFz7Recl69F43xcUJUtHy45SfKdnETqAhwmh
         rlVvC19Kg/cYaM5TV816D/K4KnpVqeNOxp5aVy6zJ2RoptVQt//iu3NxkoXTQ0dpM3Xd
         IM7h3H6DVHP/i/7A7rXY9ubmwXtcaWRKjUC/pYumKM9XwIHD//9l+IIf9+HatVghneMf
         EoGd8wNutm/6Q5uZMvoq2EPXCadjadTZ7ayGFXP/LkSJAnqX69RBFF20OYMfN8xCRtJ6
         QMzULXWen1LAIwISkSpR98EDNgRjr5wVwFH1ituyAyoFLkgUEbs5h4Rl876iD4cwwxTw
         L3FA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:ironport-sdr:from:to:cc:subject:date
         :message-id:in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=J+SwsVkIkXUHNBlwfbaRh6phQ9aQ7CdxMqodpIXtLDU=;
        b=Ggk+5tLr/dyI7cSVUI0+P8MUxkBI87xuxePWF+DqJmt8NCMirX8Za9sbzCH5AGSMhe
         oC7idwdAzxtNrdwRylhd/EMyi5EmL1czJvEMUTOUzSDo+4gh2QBQnMPu+PXA1QSug3qP
         acdkD3+5DdyfERl75qtFDl8SPBNSk6Hsm3OtE6BqMZaW7PrM/BetdwiFht7wGaXJAyhj
         KGue/sGsyYRTPERJgIOXmMf3ncu/G4y1hCtfBG7//BBwKU1TMTzEgl74s+8QYQHhyESK
         0gkmZSUfzxiRzuh8TtnfHp36Aitk5Z2kzSBN5HkpTjxD51jxytmThrPOwCYiL6wNh7Jr
         GaZg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVYnIbGyGdQPWj1vMi2KRn31LK7ZicV80MG5nT+yeyM7GdjHIuM
	DRPlabXa3zC/d0PROKYQqEo=
X-Google-Smtp-Source: APXvYqwHz1UtK6iXk1+QQfAMfcsO93CNPAp2T2TTLFW3RE8QfIrtdp5KUECH7Xz/pfeiLah50a1ecg==
X-Received: by 2002:a17:906:e52:: with SMTP id q18mr8753729eji.14.1581085620457;
        Fri, 07 Feb 2020 06:27:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:405c:: with SMTP id ns20ls59915ejb.3.gmail; Fri, 07
 Feb 2020 06:27:00 -0800 (PST)
X-Received: by 2002:a17:906:e51:: with SMTP id q17mr8779385eji.107.1581085620045;
        Fri, 07 Feb 2020 06:27:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581085620; cv=none;
        d=google.com; s=arc-20160816;
        b=WT5JxpzLqxgW3ihMpdbSYZfWuCPRPv2oP21BqKVf08KanZ9tBkDRnj3fKqNpncfo0/
         SFQDgmi3XxnOqOdJ7j6n38KQhX/v1hciBw8pUQNJvKncd/9S6jINZ63vaQtMIs35R3uL
         2vPLuSNXlx3WO7GXm3bdCRzbvC7mVLeB3g7CJl3NxWuMAYrPlCUktpjV6SZFYbqInDst
         XY4KD3kZ4m3jm/c/Ea9Fp2m872uKJ2AglJpilaWAK4hKo2ogMSRhtTaqERnn+0ruNdOH
         q7Z2CvfrtrXmK8G9K/IP1Yimg2MxNPMnh7csphRGK7nrSuwPVyh6rVQAOFG9j2DhXS0Z
         U4Gg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:ironport-sdr:dkim-signature;
        bh=9PsuMGwU7Rfc0lWpIZv6gNZKXGa5gNjoaZ19euyXmSk=;
        b=HuAiqhdoYV45Xf6i20UNlbBJoFratkz7KyMAdpZEVmBBRiopmLrssJtOvGLbcHInPY
         jvjR2WXgNX0nYXym2GTiVLqdLoxelKKdJ+WTlry4VptxEihBflCMpLuGUqfjenDUjoja
         Waw/979nqGCZo+JRx5CvI0KsC4MsgiTYsiYJJlqQBoriwL80zojTe3Lg4ujiLB2aTDgs
         0WI27c+pXdXcD1jEm1HqM+4gEDiKOFfO+856CEx8Jcf/661dkLN0W4ODdLI7VPnaFNaY
         MWlMdwlXfU6xi7wVQVFWQZjGvOVkJsAshDLAdeXVf/D2uRR6YvGcea9NeRfOVOQTI2r8
         HR+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=MjT9lM4Z;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.168 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
Received: from esa5.hc3370-68.iphmx.com (esa5.hc3370-68.iphmx.com. [216.71.155.168])
        by gmr-mx.google.com with ESMTPS id df10si169947edb.1.2020.02.07.06.26.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 07 Feb 2020 06:27:00 -0800 (PST)
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
IronPort-SDR: kMMz1oyZramg5ckLxUaxLPT0jR449vrClgivhA3Gm8ZlVz5SUPPvSuwAPwqhJfmuBnoLUKlldo
 E+J7QlpDxutZ8TB8H+ybgc3fuUAHYrc0xcqNp+avLDJaZ2qnpb18hAzEQv4+OTQdbt/JjvDsj4
 ZSVShM3LgJf74tPuBoogRoUg0zc8a2K/oa4k1g1OX6EJulg+1+I7f94ytjWhEYWSDWKiheSTej
 4qyTHoOgsuA9cFUCoVK99dgYp/L2Yj9LBmIw62LAEemsgElBhmTzRPXuV1ZG0Km2IZK39HnLOM
 BzU=
X-SBRS: 2.7
X-MesageID: 12479584
X-Ironport-Server: esa5.hc3370-68.iphmx.com
X-Remote-IP: 162.221.158.21
X-Policy: $RELAYED
X-IronPort-AV: E=Sophos;i="5.70,413,1574139600"; 
   d="scan'208";a="12479584"
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
Subject: [PATCH v3 3/4] xen: teach KASAN about grant tables
Date: Fri, 7 Feb 2020 14:26:51 +0000
Message-ID: <20200207142652.670-4-sergey.dyasli@citrix.com>
X-Mailer: git-send-email 2.17.1
In-Reply-To: <20200207142652.670-1-sergey.dyasli@citrix.com>
References: <20200207142652.670-1-sergey.dyasli@citrix.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: sergey.dyasli@citrix.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@citrix.com header.s=securemail header.b=MjT9lM4Z;       spf=pass
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
v2 --> v3: no changes

v1 --> v2: no changes

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200207142652.670-4-sergey.dyasli%40citrix.com.

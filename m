Return-Path: <kasan-dev+bncBAABBYOC4PXQKGQELNT3XZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id E7E86122E14
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Dec 2019 15:08:34 +0100 (CET)
Received: by mail-oi1-x239.google.com with SMTP id u16sf7618371oic.5
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Dec 2019 06:08:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576591713; cv=pass;
        d=google.com; s=arc-20160816;
        b=THHjBViuc8wAXUUBE+ljxHXozkbP4UCQnsdkgNCg43r8YFD0+MlQ0X/pbXruLc0VR/
         hc0GWMQLCDqUIG4x2Xd+feIRg3EBU8mydonfISVnEF+dfQA90k4a8ihUEPM1rxmVEM2Q
         B2Nj1fdyg4YdBOkBtdqPSu7RxEUuBf2npCm2qqzM8Lsk29xAVvP7JhTZcF2uWsqKVBMt
         j4ouc27ruXJ2qeM5nC1EYUA/4llTIR423d31C0hwNwShEkUpjHXpCnOzwIENHGEzSJ1l
         K4DHM4wYo2RSaJ4A4K2Ss6Mdtc3HoZj8KRwTN9Y/6kvy4Z8z1v+KEOAcSBWFZkf0hjfj
         VAbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:ironport-sdr:sender
         :dkim-signature;
        bh=8/KSY3C7pI65+3Dcf7u8KWrr8fuguVXwAszYjrFvrYo=;
        b=ooMkSsQoKhqRraxrhEjlomAHcIJpQR7OtBpG/yBlVSf0zPLiQt/9ryFTwqVGxRbYQp
         /bY5MChM1/YjafaIzur/z1POofEFyBOpTgG1A07t3c/GSaPchTa7m5BKOOTSL4t8KDwr
         SNrKq21JdGWkk53CMwBHHW+0cYmvUjhFl4U3n89P8ygNt2vkxlj3XbnS45iKpyy+3c6b
         JlyJZByFs+Byq9U7WzrPJF4HQvU1kjtt6VOFH3RNljHDbqzHVDKukNhxlD90TSw+EYMX
         cnKcxGYQNNSGYQZPIf6PR3Xr7DUHaiPmr7WA0CZhGH4ZPkt6l1bQT/TYzNNeeCBRft1d
         u7+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b="Zv/MMlrk";
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.153 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:ironport-sdr:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8/KSY3C7pI65+3Dcf7u8KWrr8fuguVXwAszYjrFvrYo=;
        b=Kq3XTWBo4iBQIgyloZQwnGfpyv5FqFQ3yd5di2Ff2IkjVOEISphZ/RCtmrgma5NK8y
         H2OxLrEfeHpVAKQ1Wro/j1YMrZBMmemVZfVKNRv7S3eo6OSw0MmaKUAHIrwmOM97AYCe
         jQYcVhyP3uQOGfWPuaP3O8FuGsNMUngZ3g0S26pYQtEnhzcYsuzjmJOZip6hULAV+SY4
         QM0YKsYtL8DNSBZl1CIaksAahs34hwXaM7HazoOXurc4yWIJ7LGwJlNHbUhBF6vAHuqb
         oN4lbTxKF7/vV0/cVS9464BDu+YSJbgT/dqDhpB2GlhlaoPZ49hQ57n+nw1TysLOPV1W
         8bqQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:ironport-sdr:from:to:cc:subject:date
         :message-id:in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8/KSY3C7pI65+3Dcf7u8KWrr8fuguVXwAszYjrFvrYo=;
        b=NeOt4rZPL0nPq6LTeaMu8DZyxHpDupd4i3VsyiNBQ2y8ZZPp9VL17oXrW4Di0b8Vd4
         ijVRK4vTA7hRZySttJobFRtTw0JLJ4rfmK6rIeEBdnKBS6xnHwrJCP2gqOc9npM4PNDR
         urWAt3Y1KrytB7s0KediCK5FEXRQH1X+/oSBgpvHIbKUdK4wWDeDiZpQhgdgNDyEjwi3
         Ca4tLZWkTTurBJzSlj6lY0YCUx2oNDQRWcD2JhbmyOS/JJcZsO2Xo+QuThU8PvPUQQzQ
         yMZi6/0sJBOZvk+L+RYCKH7xFDQVCgWSyI51OShT5gp7gv4i/8l7dWU+69tiFWm/bxQq
         bsRw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVJA5/WPoOI/F3sd7kuDEyhMl9zM5JvUqSjQYojjai9dpJEYeC5
	Yx+x+x9/+EUpLdI8s4K7z38=
X-Google-Smtp-Source: APXvYqxWyT4YXsEAMq1wKSGR2Xa6/uFQXkWqs6/EaMBkVEHJ27BPV6u15JUWobdSt0I1QoC64ZOuNg==
X-Received: by 2002:a05:6808:aa8:: with SMTP id r8mr1444796oij.7.1576591713798;
        Tue, 17 Dec 2019 06:08:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:784:: with SMTP id 126ls1539105oih.8.gmail; Tue, 17 Dec
 2019 06:08:33 -0800 (PST)
X-Received: by 2002:aca:a849:: with SMTP id r70mr426482oie.28.1576591713531;
        Tue, 17 Dec 2019 06:08:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576591713; cv=none;
        d=google.com; s=arc-20160816;
        b=lXKxVl7k6NyrccYlgg9M8xlqmYVVBBVmmpE06/o1b94ODWZWScIOWr7to1GJn5NCOk
         vz6XH+IakKFfMclLoANMudU7o5SR/nBCgYDcMxX9yjTFLErxu3uWR9Z3b+tWZ6uO9mhY
         7JmUQkhEgtt0oadc4PZH6DG0zndMZ/9ZYZdq3+SCqATDOGQ7PGqJF/OPWMhf+ZLYXDyU
         TMyKS/LRdo+R+53UxvPhyaIAmqvXryhJN8Jnd/rvfvvcLXjtdLG3rqXbvZQqShCF9rzw
         FTQFhZ5qiKo71/KgWu2uBnMpb23hO9sce+EIHSPCZ3VKj8NBC4uE9yokUCQYQSSXfwst
         /kmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:ironport-sdr:dkim-signature;
        bh=/ySfyhSZVJiwb/rWlswCpYAIJaNFz+bRgmwcQv7Dc0g=;
        b=uBMhdH6BNskg2Z7mb1g+urj0VMb7cB/UEv9epMgqRokiPYBgpdf9gtbdakwno4nT0M
         1qa0djAwS615ysH4jAvuI3kHSztzV1UC+xZJYefmSmEqoqtHpPI4QxvsrizXrvnk7B0C
         931luY2GvO25770Si3w+gdtV8JrefpyG853CWC1a+KIebLIg/IlwkADWVwR255YbPiB6
         N0lOLx4svAwI536SyiT/OpQJa/ZcOcexL8xFO9pdWxv2gGUxAiva46iVq9rhZ2dIz6AC
         iFk1v1tgyWhe4pqK/hrKviVdMocKzwe3Voou2R9Zttnr+Xk2E+CDe+bLmYcsjCoNsMWh
         xQgw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b="Zv/MMlrk";
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.153 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
Received: from esa2.hc3370-68.iphmx.com (esa2.hc3370-68.iphmx.com. [216.71.145.153])
        by gmr-mx.google.com with ESMTPS id w63si1023058oif.2.2019.12.17.06.08.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 17 Dec 2019 06:08:33 -0800 (PST)
Received-SPF: pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.153 as permitted sender) client-ip=216.71.145.153;
Received-SPF: None (esa2.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  sergey.dyasli@citrix.com) identity=pra;
  client-ip=162.221.158.21; receiver=esa2.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible
Received-SPF: Pass (esa2.hc3370-68.iphmx.com: domain of
  sergey.dyasli@citrix.com designates 162.221.158.21 as
  permitted sender) identity=mailfrom;
  client-ip=162.221.158.21; receiver=esa2.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible; x-record-type="v=spf1";
  x-record-text="v=spf1 ip4:209.167.231.154 ip4:178.63.86.133
  ip4:195.66.111.40/30 ip4:85.115.9.32/28 ip4:199.102.83.4
  ip4:192.28.146.160 ip4:192.28.146.107 ip4:216.52.6.88
  ip4:216.52.6.188 ip4:162.221.158.21 ip4:162.221.156.83
  ip4:168.245.78.127 ~all"
Received-SPF: None (esa2.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  postmaster@mail.citrix.com) identity=helo;
  client-ip=162.221.158.21; receiver=esa2.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="postmaster@mail.citrix.com";
  x-conformance=sidf_compatible
IronPort-SDR: OnwOB8MZFY2HS+S16GgpO2BJod5tklhela04K9EMRgoIVuY+Bz+fAliKtL764jlR3H7RnoDJP5
 fTRq9lM3PDOKpdhp351Sx3ptSDf6L1I2NYsKWNenDJGdSeotvZGp0NsZRrnoPNJ5IxRWhRvnSi
 x+PQgPTxbwiBlbCJ1h7yiOikObwD2yYLF+VrinHQVCXiVJ9buTQh7F+F8yTJb02QNMymHBvwH9
 xIfi1VXB6pmA92ICsMD0NODPSViQqpwUzeGxlvOMCK+g4weQE2drcJL+lPJMlMuvIAOZaWdity
 8+w=
X-SBRS: 2.7
X-MesageID: 9817030
X-Ironport-Server: esa2.hc3370-68.iphmx.com
X-Remote-IP: 162.221.158.21
X-Policy: $RELAYED
X-IronPort-AV: E=Sophos;i="5.69,325,1571716800"; 
   d="scan'208";a="9817030"
From: Sergey Dyasli <sergey.dyasli@citrix.com>
To: <xen-devel@lists.xen.org>, <kasan-dev@googlegroups.com>,
	<linux-kernel@vger.kernel.org>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Boris Ostrovsky
	<boris.ostrovsky@oracle.com>, Juergen Gross <jgross@suse.com>, "Stefano
 Stabellini" <sstabellini@kernel.org>, George Dunlap
	<george.dunlap@citrix.com>, Ross Lagerwall <ross.lagerwall@citrix.com>,
	Sergey Dyasli <sergey.dyasli@citrix.com>
Subject: [RFC PATCH 2/3] xen: teach KASAN about grant tables
Date: Tue, 17 Dec 2019 14:08:03 +0000
Message-ID: <20191217140804.27364-3-sergey.dyasli@citrix.com>
X-Mailer: git-send-email 2.17.1
In-Reply-To: <20191217140804.27364-1-sergey.dyasli@citrix.com>
References: <20191217140804.27364-1-sergey.dyasli@citrix.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: sergey.dyasli@citrix.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@citrix.com header.s=securemail header.b="Zv/MMlrk";       spf=pass
 (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.153 as
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

Otherwise it produces lots of false positives.

Signed-off-by: Ross Lagerwall <ross.lagerwall@citrix.com>
Signed-off-by: Sergey Dyasli <sergey.dyasli@citrix.com>
---
 drivers/xen/grant-table.c | 5 ++++-
 1 file changed, 4 insertions(+), 1 deletion(-)

diff --git a/drivers/xen/grant-table.c b/drivers/xen/grant-table.c
index 49b381e104ef..0f844c14d5b9 100644
--- a/drivers/xen/grant-table.c
+++ b/drivers/xen/grant-table.c
@@ -1049,6 +1049,7 @@ int gnttab_map_refs(struct gnttab_map_grant_ref *map_ops,
 			foreign = xen_page_foreign(pages[i]);
 			foreign->domid = map_ops[i].dom;
 			foreign->gref = map_ops[i].ref;
+			kasan_alloc_pages(pages[i], 0);
 			break;
 		}
 
@@ -1085,8 +1086,10 @@ int gnttab_unmap_refs(struct gnttab_unmap_grant_ref *unmap_ops,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191217140804.27364-3-sergey.dyasli%40citrix.com.

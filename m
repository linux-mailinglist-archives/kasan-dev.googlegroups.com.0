Return-Path: <kasan-dev+bncBC2OPIG4UICBBXGH76DAMGQESFDKR3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id EB23C3BA700
	for <lists+kasan-dev@lfdr.de>; Sat,  3 Jul 2021 06:13:17 +0200 (CEST)
Received: by mail-ot1-x340.google.com with SMTP id e14-20020a0568301f2eb0290405cba3beedsf7594763oth.13
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Jul 2021 21:13:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625285596; cv=pass;
        d=google.com; s=arc-20160816;
        b=S9GWlQ6dzp7WxTVbicuKwXQl4QFnfn3HZ7TtbGxDjk7ocMsEoz+8Kk9gfOOAvIPjcg
         M7jhTToyIDnNqP170grtwILANllb0hHNQLuqOFWmHbgI+3tUsezn6bpc9MGkdalQCcng
         Jwp8UpQ3Jo7+aJRItwGRajGDSUCgziIMe6iJEp2shUTsaCneqznZ4v5BOnI1f17OoyFy
         PXX/Aq8bOj81nmvx9tHDtT2IQkQBDtMwXtxpYGa05zWqXjL9g/Y54yqq6KqLAqv8G8Pg
         7nrY5bXzXh3SUjr8LD2Ospy8qbrIbhsY5BE2hZPBp+Ox4TftYsECUnnf7iYGaUujzkQw
         23qg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=hMjJgUkbsZRL6me7ntECjt5uhBQ0Boo/reDXvjAnXP8=;
        b=h4rlYnLE44Smc8lDjE7rtHD3ALiZsHtjvYMQl+8sixhjWQjPXmwADff6QjlIWXJMnw
         2zN/kNnIgnVqoCZR06osGm/Aoa60iJkLiV+f4PMV2YV7A1atzrBhyYEomFSrd+MDQHWT
         s+dLhfQSAfDmH1OKbfizvEDoNQ+Yqyil0+ks6Cpmd3iHKEfrpMK0vPPP+5pkM32G/MOL
         1pM7NC5C+iOgbU4BdW9PmJy1pldfe0wW0iXSiiBwZgVuGczriPzoYo551H1pPT9SjbJc
         1d3nNOYTyX66cwASbvfQ+zQphiA58nGB35Ba4QNSlUSlJOyxAO+EUJQW1fe5V4RlemHZ
         PAYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of hdanton@sina.com designates 202.108.3.11 as permitted sender) smtp.mailfrom=hdanton@sina.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hMjJgUkbsZRL6me7ntECjt5uhBQ0Boo/reDXvjAnXP8=;
        b=ASAHIntkp4b/IGeN0rGZKchJHqPkDWQQ4aUKlSrPmvehkPs2qcaXAn0HL7qPH8Po95
         egY5OVT0iqH/gIVij8YjLUdsfVzPsDs/Uc572LhaQuA9ThEdwYPTnQQ5K1CMYTCYdR/9
         pJ0X4uD2lMsoi5j83eIbRKzViY1RQffXUdzJ78NTQ/Jbo4YDNo6BNMJV6ZZYK5PYTEOz
         PkxBSz3+eyaV5gBtBzVWQCuCrjo6+xzyF+Qv8ny1zHKQX05TZKbNe4FVRVKymqLqQusU
         VTxOOu9Oul8th2MXUixISZtxMeyxb+BT/TgCp8BVAYq9GSr9BP4ZQx4QR5X54FMco2Pb
         OBpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hMjJgUkbsZRL6me7ntECjt5uhBQ0Boo/reDXvjAnXP8=;
        b=QNu8HqSXL7lXWwdRBmNZWy1EoCwkWLfPunl+8+CpYG+Ez8MKX6SgUDH6AQSyWMN4nt
         e65aI3J9O7ZlD1BaMbAZsMzAOCAYOaxqUOo5wPiBdgHfFko0z4RJFvkKrAHvS6U4MJKr
         YfLkSJS6hGyvA0cIB9l0Oe+m/JarsPK22SLWMtIX+m5YhVx8JVKIGTd7WxwOvN5OF2z9
         m7bIlB+il5iu1jOZeyZS8+LDQ3zvzP2/CvsymU8ts5SUefKxVc/eh4qQVrVjZH9NYpqQ
         bZoOwMK4yRYNwnHh0iauRp8SV12NfK9sq8TC6ifImmHa6A3oWtExZdc7BoRfOqS/DYbe
         idhw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530NZkIqM5ObwE/UdhFQbxa6oq9rBQrWV4btg8aT4pHmJRPvbq5K
	vMiWuZgHpFU5np/yaW04J/o=
X-Google-Smtp-Source: ABdhPJx8dmhePdH+HswGGfvbQUuT6KtjQNXuHJMCQvbJ7YIzJGiiZ0J/ogztoP8F2BtLtvsoJqu7xA==
X-Received: by 2002:a05:6808:9b7:: with SMTP id e23mr2279971oig.2.1625285596720;
        Fri, 02 Jul 2021 21:13:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:d194:: with SMTP id j20ls1075730oor.1.gmail; Fri, 02 Jul
 2021 21:13:16 -0700 (PDT)
X-Received: by 2002:a4a:98b0:: with SMTP id a45mr2418655ooj.22.1625285596266;
        Fri, 02 Jul 2021 21:13:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625285596; cv=none;
        d=google.com; s=arc-20160816;
        b=fU/XqKBlRFDw+MXdd1FrMcZupSPQ4Ee+DhDabMhe8MWCsZWTriqk2JQxBs/2YPV0Ak
         La4ot0l32fF1N1yM/Qmw05ncXO0+bWN0wa178OUhlg07xDguaIqxjFTP6VuohX/2dhaM
         ewpCwzQWIZnod8797Evtf8b8Nedqf9vkqtRS7uudvikRKqQgWdMdlVVhIDLe40FRhz+c
         xUVxNmrNG8ViDXxmII743MOn99XePpKZWPl/6jNbElUYEX68YPC1JxPBmluMHXZCvTIr
         xrcaX65IS9zxkh/GVdmiYjD51g3XZYJyGurtHq2Sakl9O/2t73GiAK/1dXnI/YQSPrmo
         xZug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=OIF52H2ffPsLKh/Ou9u81rLit7CLoqoduFEdRBDqN2k=;
        b=LdY04Ncw6QwCf0qscbft3ONfIPgey5/eav9yajBZqaq4JICWruRZqdfYgfO8mwPmeE
         HKl/TnOI014kvQ9hYTG4vmTiA+6ux7nIrpBJbuR8CjB6VEA2IJrsDdVUubDOkZ3XySDl
         GnyExlOavAO7RQDtoENo39BLZ7Vj2rm/UG9ymXiITBzhrRgiyJ9woN/yZMeZxLQQ778/
         a/fqG6w7oWdNDTxvquKU6U2jfoiUSdp9fDKhgjsvQQbFgQOE3azmICbhiIG38yEHlDmL
         ddQmVa/2F8LniML+dkwZO8hu2d94KhzscyYyjUv5PfdzyBzATJEoaPZ0Pis6o23HDjAy
         uxwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of hdanton@sina.com designates 202.108.3.11 as permitted sender) smtp.mailfrom=hdanton@sina.com
Received: from r3-11.sinamail.sina.com.cn (r3-11.sinamail.sina.com.cn. [202.108.3.11])
        by gmr-mx.google.com with SMTP id m16si598509oih.4.2021.07.02.21.13.15
        for <kasan-dev@googlegroups.com>;
        Fri, 02 Jul 2021 21:13:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of hdanton@sina.com designates 202.108.3.11 as permitted sender) client-ip=202.108.3.11;
Received: from unknown (HELO localhost.localdomain)([222.130.247.133])
	by sina.com (172.16.97.27) with ESMTP
	id 60DFE3D100019124; Sat, 3 Jul 2021 12:13:07 +0800 (CST)
X-Sender: hdanton@sina.com
X-Auth-ID: hdanton@sina.com
X-SMAIL-MID: 45813349283235
From: Hillf Danton <hdanton@sina.com>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: syzbot <syzbot+e45919db2eab5e837646@syzkaller.appspotmail.com>,
	Mel Gorman <mgorman@techsingularity.net>,
	kasan-dev <kasan-dev@googlegroups.com>,
	akpm@linux-foundation.org,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	syzkaller-bugs@googlegroups.com
Subject: Re: [syzbot] upstream test error: BUG: sleeping function called from invalid context in stack_depot_save
Date: Sat,  3 Jul 2021 12:12:56 +0800
Message-Id: <20210703041256.212-1-hdanton@sina.com>
In-Reply-To: <CACT4Y+ZY4sOXQ0F5cumzpwo2V8TLN+kDAj=eAYWX4f5sqg993w@mail.gmail.com>
References: <0000000000009e7f6405c60dbe3b@google.com>
MIME-Version: 1.0
X-Original-Sender: hdanton@sina.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of hdanton@sina.com designates 202.108.3.11 as permitted
 sender) smtp.mailfrom=hdanton@sina.com
Content-Type: text/plain; charset="UTF-8"
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

On Thu, 1 Jul 2021 13:10:37 +0200 Dmitry Vyukov wrote:
>On Thu, Jul 1, 2021 at 1:00 PM syzbot wrote:
>>
>> Hello,
>>
>> syzbot found the following issue on:
>>
>> HEAD commit:    dbe69e43 Merge tag 'net-next-5.14' of git://git.kernel.org..
>> git tree:       upstream
>> console output: https://syzkaller.appspot.com/x/log.txt?x=1216d478300000
>> kernel config:  https://syzkaller.appspot.com/x/.config?x=47e4697be2f5b985
>> dashboard link: https://syzkaller.appspot.com/bug?extid=e45919db2eab5e837646
>>
>> IMPORTANT: if you fix the issue, please add the following tag to the commit:
>> Reported-by: syzbot+e45919db2eab5e837646@syzkaller.appspotmail.com
>
>+kasan-dev@ for for stack_depot_save warning
>
>> BUG: sleeping function called from invalid context at mm/page_alloc.c:5179
>> in_atomic(): 0, irqs_disabled(): 1, non_block: 0, pid: 8436, name: syz-fuzzer
>> INFO: lockdep is turned off.
>> irq event stamp: 0
>> hardirqs last  enabled at (0): [<0000000000000000>] 0x0
>> hardirqs last disabled at (0): [<ffffffff814406db>] copy_process+0x1e1b/0x74c0 kernel/fork.c:2061
>> softirqs last  enabled at (0): [<ffffffff8144071c>] copy_process+0x1e5c/0x74c0 kernel/fork.c:2065
>> softirqs last disabled at (0): [<0000000000000000>] 0x0
>> CPU: 1 PID: 8436 Comm: syz-fuzzer Tainted: G        W         5.13.0-syzkaller #0
>> Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
>> Call Trace:
>>  __dump_stack lib/dump_stack.c:79 [inline]
>>  dump_stack_lvl+0xcd/0x134 lib/dump_stack.c:96
>>  ___might_sleep.cold+0x1f1/0x237 kernel/sched/core.c:9153
>>  prepare_alloc_pages+0x3da/0x580 mm/page_alloc.c:5179
>>  __alloc_pages+0x12f/0x500 mm/page_alloc.c:5375
>>  alloc_pages+0x18c/0x2a0 mm/mempolicy.c:2272
>>  stack_depot_save+0x39d/0x4e0 lib/stackdepot.c:303
>>  save_stack+0x15e/0x1e0 mm/page_owner.c:120
>>  __set_page_owner+0x50/0x290 mm/page_owner.c:181
>>  prep_new_page mm/page_alloc.c:2445 [inline]
>>  __alloc_pages_bulk+0x8b9/0x1870 mm/page_alloc.c:5313
>>  alloc_pages_bulk_array_node include/linux/gfp.h:557 [inline]
>>  vm_area_alloc_pages mm/vmalloc.c:2775 [inline]
>>  __vmalloc_area_node mm/vmalloc.c:2845 [inline]
>>  __vmalloc_node_range+0x39d/0x960 mm/vmalloc.c:2947
>>  __vmalloc_node mm/vmalloc.c:2996 [inline]
>>  vzalloc+0x67/0x80 mm/vmalloc.c:3066
>>  n_tty_open+0x16/0x170 drivers/tty/n_tty.c:1914
>>  tty_ldisc_open+0x9b/0x110 drivers/tty/tty_ldisc.c:464
>>  tty_ldisc_setup+0x43/0x100 drivers/tty/tty_ldisc.c:781
>>  tty_init_dev.part.0+0x1f4/0x610 drivers/tty/tty_io.c:1461
>>  tty_init_dev include/linux/err.h:36 [inline]
>>  tty_open_by_driver drivers/tty/tty_io.c:2102 [inline]
>>  tty_open+0xb16/0x1000 drivers/tty/tty_io.c:2150
>>  chrdev_open+0x266/0x770 fs/char_dev.c:414
>>  do_dentry_open+0x4c8/0x11c0 fs/open.c:826
>>  do_open fs/namei.c:3361 [inline]
>>  path_openat+0x1c0e/0x27e0 fs/namei.c:3494
>>  do_filp_open+0x190/0x3d0 fs/namei.c:3521
>>  do_sys_openat2+0x16d/0x420 fs/open.c:1195
>>  do_sys_open fs/open.c:1211 [inline]
>>  __do_sys_openat fs/open.c:1227 [inline]
>>  __se_sys_openat fs/open.c:1222 [inline]
>>  __x64_sys_openat+0x13f/0x1f0 fs/open.c:1222
>>  do_syscall_x64 arch/x86/entry/common.c:50 [inline]
>>  do_syscall_64+0x35/0xb0 arch/x86/entry/common.c:80
>>  entry_SYSCALL_64_after_hwframe+0x44/0xae

One of the quick fixes is move preparing new page out of the local lock (with
irq disabled) if it is difficult to add changes in saving stack.

+++ x/mm/page_alloc.c
@@ -5231,6 +5231,7 @@ unsigned long __alloc_pages_bulk(gfp_t g
 	gfp_t alloc_gfp;
 	unsigned int alloc_flags = ALLOC_WMARK_LOW;
 	int nr_populated = 0, nr_account = 0;
+	LIST_HEAD(head);
 
 	if (unlikely(nr_pages <= 0))
 		return 0;
@@ -5308,17 +5309,29 @@ unsigned long __alloc_pages_bulk(gfp_t g
 			break;
 		}
 		nr_account++;
-
-		prep_new_page(page, 0, gfp, 0);
-		if (page_list)
-			list_add(&page->lru, page_list);
-		else
-			page_array[nr_populated] = page;
+		list_add(&page->lru, &head);
 		nr_populated++;
 	}
 
 	local_unlock_irqrestore(&pagesets.lock, flags);
 
+	list_for_each_entry(page, &head, lru)
+		prep_new_page(page, 0, gfp, 0);
+
+	if (page_list)
+		list_splice(&head, page_list);
+	else {
+		int i; 
+
+		for (i = 0; i < nr_pages && !list_empty(&head); i++) {
+			/* Skip existing pages */
+			if (page_array[i])
+				continue;
+			page = list_first_entry(&head, struct page, lru);
+			list_del_init(&page->lru);
+			page_array[i] = page;
+		}
+	}
 	__count_zid_vm_events(PGALLOC, zone_idx(zone), nr_account);
 	zone_statistics(ac.preferred_zoneref->zone, zone, nr_account);
 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210703041256.212-1-hdanton%40sina.com.

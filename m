Return-Path: <kasan-dev+bncBDA5BKNJ6MIBB6XBZGGAMGQE25OIH7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 356A245073A
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Nov 2021 15:38:51 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id h7-20020adfaa87000000b001885269a937sf3645454wrc.17
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Nov 2021 06:38:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636987131; cv=pass;
        d=google.com; s=arc-20160816;
        b=NTUD/un9Zt6cj93AtnT3baBiCK5gWjBCIg+Y9HMeYrpayab6+OESWmJ1l8/VGBzOo9
         lNITm0xetae9vHMaG1iEe4921rwCusWwvt7w/sJzzCYg1uS0L06cN22mhKVSwXFq5kCu
         hyP1TF//ekOF6ocP2TExQI6C5Rwjrooni0c6YQQjzG9WD3EdkpRX3pPjprGH+cVkycR/
         PKh3Hso7u01HYfrbzqiXlwz35e7F9apWj/3q97R9/+wySAi9nl9HdftoFJBXFgsqHctC
         szYGq6/n1ui2tk55HOBvL8A0OkXSLzxxJtGyjvmehP4PX8Mk8fdHcdfyk+RT2AjFhdwN
         hQlA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:organization:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=mHDZLG4bL9+uXedtNVSbAp2SWTLFS6+UFr+os2xZG5Q=;
        b=wiSQCDBTJOlsjFlqFBTdO0is4REz9cdoz26sNIeWi2E84obHcau+tk97DhFEPeOwkD
         vxigUSi/mnkccqRyf5DhzyncHoH0Rjt1HdtSDuiN9u72dNqXMyF9GwszS+HvITl3iQ2h
         4Lsgb3+mdTY8S3MLTIHfvLJeV6FCertae7nWtDvzmYHU9MIZQh0dpMhI/xjQg3MiR9SS
         AsD43SelUC8E9dA+CQ4NwCrq1HuuTdYWAoptmDrj8ltbXJclrU4GpDirZudDWTyKZ5pF
         gdE1kXxA1o6aB5y03FykjcC/0r0s4E+/jcKdUwrp4mqMdYq0vpc+1M/3lQsw43f3xGtM
         UjZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of andriy.shevchenko@linux.intel.com designates 192.55.52.136 as permitted sender) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:organization:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mHDZLG4bL9+uXedtNVSbAp2SWTLFS6+UFr+os2xZG5Q=;
        b=QwZHX6UziO/1W1WdHrbVXwB7uC9nUF6A3IRF+i/aLSuXGdWYVdgL5Jaki5J/4JDkO+
         l7yDtZmcXVyuDinlSsPaqX18jPfvSIGYIp2vueu1KIOJ1VvgEOg8WRpljLlzBSnIRIx9
         Lbo52G6Qg+BcOtWsbCh6FfTopnKijB11KDrSSPCQWnUBNlVWtoWeLC+SzEOSM5I4qspk
         cCb5Esdt1L+DCGiEmE79+IaPBjVS3EIz1o8a33Qg4GNya3EcW2XLgEI+BHDxBgiV86N7
         RS+R//8N0A9f/Wf3FaxkctG0VVrlMOUXWX7rjESR0ZT03+Fi88ht5CL+dna64RHGF8Uc
         rkmw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :organization:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mHDZLG4bL9+uXedtNVSbAp2SWTLFS6+UFr+os2xZG5Q=;
        b=b03LyK7eK8CZaTBL9ETBycGej+QmBgTyovsUHgpJaF7zRDNo9X8jCeFNzZU460NEI5
         Xtb4HYhw1sAuMppnmXRffhDSXUX54QatVV+Szkwm87hhRwxaIubm/CvWV7ly+f2eSKaJ
         GLI19Kz7uOU3uDhSngPKHAu0w37lqsJPAuNlR5KhpCo/rU5pP3D4sZQCfTsroeUSV1m9
         MCIMUHvwuVqn+JElhe08FbmYByN4tEQOu4J8yjp68Kf3pokoLHSukoB0hvOjn4Iav2OZ
         WItzAfY0xeF20Ezo+tTqTr9klBOQchte6b4Mnm0VkgbqQLs7TvzDYicEZBRG69LV5LPw
         3x8w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530iWj7hwn2cf597wFFbOZ1EGAnb2ppK7ruA334vrjRoeJjWZf43
	/OtbTDH1oGylGPs73hayOF0=
X-Google-Smtp-Source: ABdhPJwkoHn3G6wpzk0SN5q0+gZ8ngFw7JOR1e35pm/9K95wUyqCrv2mE61EjrjwvYU78XrTx7foYg==
X-Received: by 2002:a05:600c:190b:: with SMTP id j11mr42211252wmq.112.1636987130924;
        Mon, 15 Nov 2021 06:38:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4092:: with SMTP id o18ls10674173wrp.1.gmail; Mon, 15
 Nov 2021 06:38:50 -0800 (PST)
X-Received: by 2002:adf:ecce:: with SMTP id s14mr47224493wro.98.1636987130082;
        Mon, 15 Nov 2021 06:38:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636987130; cv=none;
        d=google.com; s=arc-20160816;
        b=Yo21FrstfPojsce8vSGE/8nRs8+9K24xuEX4qssDrclxt99S6d8uujz/cI9nxN9R44
         yQBCzJ5GerTWfz7t0b4zbhxWMtxw9/1vezaWlmKcKEK3fTqSSlQNEhRvfHSL8OZ3Qjo1
         fx0QQCKFOTnVHJyujkzcfhouYKHLzatoBlcWMzPbg2JUL82VMlPsmsiUAhPZgHMjz3cR
         XHKOoq2FZjzymu4UR+ALbUXhUUNmqpGnnh5p+Kev1BC6W9D9Ck3k1cORpa4B2Othwppn
         8WPSaSxXr0HUq+fSi5SJmiVfuQ11JWpdu2rSFx+1onspjwDzfbMR6CVhglgFJE2L9r1K
         3Dcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=organization:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date;
        bh=BT1HOyTQCbZSlZk1X7hXxDLrpfeioqn533ft3E8PHbE=;
        b=0vO72HSKd1KbmozHpG4nZpZRYy+GzTN14OWG2uqnhcV8nwF0hHz32GYhtbYV5hl2O6
         hUYb9Po6plotx2ZUtX+OQNJGoACuecdeMHYDlL3cy7RLoM0TzwXE0ZswnNoc+4jIuG+w
         Qu58YYqhfwqFr1CIwTYASRURFykkBzWxvikCEqT+/wZcp5aaA/nm4dcZu/wfzSapQG9z
         yZ5oJVvEvAI2cH49VbfjbepneNtl+V/nWhV+5XZJPYBCBlGL8Nofpr85jsWgNG0UO4Gj
         mcWgXieE1ZtCDY8KsI/FqXgIchL1WavEAIsirrdPuEW6uIFoMQ+vlQomsrFOU7sC+suW
         7dpg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of andriy.shevchenko@linux.intel.com designates 192.55.52.136 as permitted sender) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga12.intel.com (mga12.intel.com. [192.55.52.136])
        by gmr-mx.google.com with ESMTPS id c2si1471073wmq.2.2021.11.15.06.38.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 15 Nov 2021 06:38:49 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of andriy.shevchenko@linux.intel.com designates 192.55.52.136 as permitted sender) client-ip=192.55.52.136;
X-IronPort-AV: E=McAfee;i="6200,9189,10168"; a="213483888"
X-IronPort-AV: E=Sophos;i="5.87,236,1631602800"; 
   d="scan'208";a="213483888"
Received: from orsmga003.jf.intel.com ([10.7.209.27])
  by fmsmga106.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 15 Nov 2021 06:38:47 -0800
X-IronPort-AV: E=Sophos;i="5.87,236,1631602800"; 
   d="scan'208";a="453834726"
Received: from smile.fi.intel.com ([10.237.72.184])
  by orsmga003-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 15 Nov 2021 06:38:44 -0800
Received: from andy by smile.fi.intel.com with local (Exim 4.95)
	(envelope-from <andriy.shevchenko@linux.intel.com>)
	id 1mmd7z-0077SS-86;
	Mon, 15 Nov 2021 16:38:35 +0200
Date: Mon, 15 Nov 2021 16:38:35 +0200
From: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
To: Marco Elver <elver@google.com>
Cc: Steven Rostedt <rostedt@goodmis.org>, Ingo Molnar <mingo@redhat.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Petr Mladek <pmladek@suse.com>,
	Luis Chamberlain <mcgrof@kernel.org>, Wei Liu <wei.liu@kernel.org>,
	Mike Rapoport <rppt@kernel.org>, Arnd Bergmann <arnd@arndb.de>,
	John Ogness <john.ogness@linutronix.de>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	Alexander Popov <alex.popov@linux.com>
Subject: Re: [PATCH] panic: use error_report_end tracepoint on warnings
Message-ID: <YZJw69RdPES7gHBM@smile.fi.intel.com>
References: <20211115085630.1756817-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211115085630.1756817-1-elver@google.com>
Organization: Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
X-Original-Sender: andriy.shevchenko@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: best guess record for domain of andriy.shevchenko@linux.intel.com
 designates 192.55.52.136 as permitted sender) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On Mon, Nov 15, 2021 at 09:56:30AM +0100, Marco Elver wrote:
> Introduce the error detector "warning" to the error_report event and use
> the error_report_end tracepoint at the end of a warning report.
> 
> This allows in-kernel tests but also userspace to more easily determine
> if a warning occurred without polling kernel logs.

...

>  enum error_detector {
>  	ERROR_DETECTOR_KFENCE,
> -	ERROR_DETECTOR_KASAN
> +	ERROR_DETECTOR_KASAN,
> +	ERROR_DETECTOR_WARN

...which exactly shows my point (given many times somewhere else) why comma
is good to have when we are not sure the item is a terminator one in the enum
or array of elements.

>  };

-- 
With Best Regards,
Andy Shevchenko


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YZJw69RdPES7gHBM%40smile.fi.intel.com.
